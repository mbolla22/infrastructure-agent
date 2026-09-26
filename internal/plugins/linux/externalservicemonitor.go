// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"
)

var esmlog = log.WithPlugin("ExternalServiceMonitor")

var externalServiceMonitorPluginID = ids.PluginID{"external", "service_monitor"}

// defaultTargetsConfigPath is where operators list the ports to watch.
// Adding a new integration to monitor (Kafka today, anything else tomorrow)
// is a config-file edit here, not a code change or rebuild.
const defaultTargetsConfigPath = "/etc/newrelic-infra/external-service-monitor.yml"

// JMXMetric is the one JMX attribute a component's span should carry, used
// only by the kafka/spans-style JMX plugin - the caller-monitor plugin
// ignores this block entirely. Host defaults to "localhost" when omitted;
// set it explicitly to poll a broker whose JMX endpoint lives on a
// different host than this infra-agent instance.
type JMXMetric struct {
	Host           string `yaml:"host,omitempty"`
	Port           int    `yaml:"port"`
	Bean           string `yaml:"bean"`
	Attribute      string `yaml:"attribute"`
	AttributeLabel string `yaml:"attribute_label"`
}

func (j JMXMetric) hostOrDefault() string {
	if j.Host == "" {
		return "localhost"
	}
	return j.Host
}

// BrokerConfig is one broker within a cluster. An integration can list any
// number of these - unlike MonitorComponent, brokers are explicitly a list
// because there can be many, each independently identified by BrokerID (not
// by a name string), matching how New Relic's own entity model distinguishes
// brokers within a cluster by (broker.id, cluster name), not by hostname or
// position.
type BrokerConfig struct {
	BrokerID string     `yaml:"broker_id"`
	Port     int        `yaml:"port"`
	JMX      *JMXMetric `yaml:"jmx,omitempty"`
	// TopicJMX is an additional, optional per-topic metric (e.g. Kafka's
	// BrokerTopicMetrics bean with a topic= tag). Purely additive: when nil,
	// behavior is identical to before this field existed.
	TopicJMX *JMXMetric `yaml:"topic_jmx,omitempty"`
}

// MonitorComponent is one named, port-bound piece of an integration that
// is NOT a broker - e.g. kafka's "producer", "consumer". Port/caller-
// discovery is used by the external-service-monitor plugin; JMX/SpanRole are
// used by the JMX-metric span plugin. Either plugin ignores fields it
// doesn't need.
type MonitorComponent struct {
	Name string     `yaml:"name"`
	Port int        `yaml:"port"`
	JMX  *JMXMetric `yaml:"jmx,omitempty"`
	// TopicJMX is an additional, optional per-topic metric for this
	// component (e.g. producer-topic-metrics / consumer-fetch-manager-
	// metrics with a topic= tag). Purely additive: when nil, behavior is
	// identical to before this field existed.
	TopicJMX *JMXMetric `yaml:"topic_jmx,omitempty"`
	// SpanRole marks this component as a caller side ("producer"/"consumer")
	// that should be paired against every one of the integration's brokers to
	// form linked span pairs (one pair per broker per poll, since a real
	// client can reach any broker - there is no single fixed "the broker"
	// once there is more than one).
	SpanRole string `yaml:"span_role,omitempty"`
}

// SQLMetric is one SQL query a database-backed component's span should
// carry, used only by the kafka/spans-style span plugin - the caller-monitor
// plugin only needs Port (on DatabaseConfig) to find callers, and ignores
// this block entirely. DSN carries the full connection string (host, port,
// dbname, user, password, sslmode, ...) since that's how database/sql
// drivers already expect it - no need to reinvent host/port/user fields.
type SQLMetric struct {
	Driver         string `yaml:"driver"`
	DSN            string `yaml:"dsn"`
	Query          string `yaml:"query"`
	AttributeLabel string `yaml:"attribute_label"`
}

// DatabaseConfig is a downstream database that a component (typically a
// consumer) writes into. Paired against every component with SpanRole
// "consumer" in the same integration - a database sits downstream of the
// consumer, not the producer, mirroring the actual data flow.
type DatabaseConfig struct {
	Name string     `yaml:"name"`
	Port int        `yaml:"port"`
	SQL  *SQLMetric `yaml:"sql,omitempty"`
}

// MonitorIntegration is one integration (kafka today, others later): its
// cluster identity, its topic (single-topic setups only, for now - the name
// to stamp on any topic_jmx attributes below), its brokers (a list - there
// can be more than one), the other components (producer/consumer, etc.)
// operators want visibility on, and an optional downstream database that a
// consumer writes into.
type MonitorIntegration struct {
	Name        string             `yaml:"name"`
	ClusterName string             `yaml:"cluster_name,omitempty"`
	Topic       string             `yaml:"topic,omitempty"`
	Brokers     []BrokerConfig     `yaml:"brokers,omitempty"`
	Components  []MonitorComponent `yaml:"components"`
	Database    *DatabaseConfig    `yaml:"database,omitempty"`
}

type monitorTargetsFile struct {
	Integrations []MonitorIntegration `yaml:"integrations"`
}

// loadMonitorIntegrations returns the raw, unflattened integration/component
// tree, for plugins (like the JMX span plugin) that need to correlate
// sibling components (e.g. "producer" and "broker") within one integration.
func loadMonitorIntegrations(path string) ([]MonitorIntegration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f monitorTargetsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Integrations, nil
}

// ExternalServiceTarget is a port this plugin watches for callers that have
// NO dedicated per-integration plugin - i.e. genuinely outside the
// explicitly modeled setup. It is read from its own top-level
// "external_services" config key, entirely separate from "integrations"
// (kafkaspans.go's config) and "proxies" (nginxspans.go's config), so this
// plugin can never accidentally re-watch a port another plugin already
// covers precisely.
type ExternalServiceTarget struct {
	Name string `yaml:"name"`
	Port int    `yaml:"port"`
	// DestinationService lets the destination span reuse an identity that
	// already exists elsewhere (e.g. "kafka-broker-0" from brokerServiceName)
	// so a caller discovered into an already-known destination lands on
	// that same node instead of minting a duplicate one. Leave unset for a
	// destination with no existing identity - it falls back to Name.
	DestinationService string `yaml:"destination_service,omitempty"`
}

type externalServicesFile struct {
	ExternalServices []ExternalServiceTarget `yaml:"external_services"`
}

func loadMonitorTargets(path string) ([]ExternalServiceTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f externalServicesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.ExternalServices, nil
}

// brokerServiceName is the ONE naming rule for "this broker" as a New Relic
// service.name, shared by every plugin that emits a span representing a
// broker (jmx/spans and external/service_monitor today). Both plugins are
// describing the same physical broker process, so they must agree on its
// name - otherwise the same broker fragments into unrelated service
// identities depending on which plugin happened to observe it.
func brokerServiceName(integrationName, brokerID string) string {
	return integrationName + "-broker-" + brokerID
}

// databaseServiceName is the same idea as brokerServiceName, but for a
// downstream database (jmx/spans and external/service_monitor both emit
// spans representing it, and must agree on its name).
func databaseServiceName(integrationName, databaseName string) string {
	return integrationName + "-" + databaseName
}

// externalServiceName is the ONE identity used for a caller this agent
// cannot attribute to a known, configured component - shared by
// external/service_monitor and nginx/spans' own fallback path. Naming it
// "external-service-<processname>" per discovered process would fragment
// one real concept ("something outside our modeled setup") into as many
// service identities as there happen to be distinct process names - the
// resolved process name is still recorded as the caller.process attribute,
// just not used to split the service identity.
const externalServiceName = "external-service"

type tcpConn struct {
	remoteIP   string
	remotePort int
	localPort  int
	inode      string
}

type ExternalServiceMonitorPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	targets   []ExternalServiceTarget
}

func NewExternalServiceMonitorPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	targets, err := loadMonitorTargets(defaultTargetsConfigPath)
	if err != nil {
		esmlog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no external-service-monitor targets config found or failed to parse; nothing will be monitored until it exists")
	}

	return &ExternalServiceMonitorPlugin{
		PluginCommon: agent.PluginCommon{ID: externalServiceMonitorPluginID, Context: ctx},
		frequency:    15 * time.Second,
		targets:      targets,
	}
}

// hexIPToDotted converts the little-endian hex-encoded IPv4 address used in
// /proc/net/tcp (e.g. "0100007F") into dotted-quad form ("127.0.0.1").
// /proc/net/tcp6 encodes IPv4-mapped addresses as 32 hex chars; the real IPv4
// bytes are always the last 8 of those, so trim before decoding.
func hexIPToDotted(hexIP string) string {
	if len(hexIP) == 32 {
		hexIP = hexIP[24:]
	}
	if len(hexIP) != 8 {
		return hexIP
	}
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		b := hexIP[len(hexIP)-2*(i+1) : len(hexIP)-2*i]
		v, err := strconv.ParseInt(b, 16, 32)
		if err != nil {
			return hexIP
		}
		parts[i] = strconv.FormatInt(v, 10)
	}
	return strings.Join(parts, ".")
}

// findConnectionsToPort scans /proc/net/tcp and /proc/net/tcp6 for ESTABLISHED
// (st=01) connections whose remote port matches targetPort - i.e. the
// caller's side of the connection, not the listening service's own side.
func findConnectionsToPort(targetPort int) ([]tcpConn, error) {
	var results []tcpConn
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		conns, err := parseProcNetTCP(path, targetPort)
		if err != nil {
			if os.IsNotExist(err) {
				continue // tcp6 may not exist if IPv6 is disabled
			}
			return results, err
		}
		results = append(results, conns...)
	}
	return results, nil
}

func parseProcNetTCP(path string, targetPort int) ([]tcpConn, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var results []tcpConn
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header or blank
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1] // e.g. 0100007F:2384
		remAddr := fields[2]
		state := fields[3]
		inode := fields[9]

		// We want the CALLER's side of the connection: the row whose remote
		// port is the monitored service's port, not the service's own
		// listening/accepted row (whose inode would resolve back to the
		// monitored service's own PID instead of the caller's).
		remParts := strings.Split(remAddr, ":")
		if len(remParts) != 2 {
			continue
		}
		remotePort, err := strconv.ParseInt(remParts[1], 16, 32)
		if err != nil || int(remotePort) != targetPort {
			continue
		}
		if state != "01" { // 01 = ESTABLISHED
			continue
		}

		localParts := strings.Split(localAddr, ":")
		if len(localParts) != 2 {
			continue
		}
		localPort, _ := strconv.ParseInt(localParts[1], 16, 32)

		results = append(results, tcpConn{
			remoteIP:   hexIPToDotted(remParts[0]),
			remotePort: int(remotePort),
			localPort:  int(localPort),
			inode:      inode,
		})
	}
	return results, nil
}

// findPidForInode walks /proc/<pid>/fd for every running process to find which
// one owns the given socket inode, returning its PID and command name.
func findPidForInode(inode string) (pid int, comm string, ok bool) {
	if inode == "" || inode == "0" {
		return 0, "", false
	}
	target := "socket:[" + inode + "]"

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", false
	}

	for _, e := range procEntries {
		pidNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pidNum)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied or process exited, skip
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if link == target {
				commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pidNum))
				name := "unknown"
				if err == nil {
					name = strings.TrimSpace(string(commBytes))
				}
				return pidNum, name, true
			}
		}
	}
	return 0, "", false
}

// pollTarget discovers real callers into target.Port and, for each one,
// submits two spans sharing one trace: the caller (parent, it initiated
// the connection) -> the target (child, it accepted it) - instead of
// leaving each caller as an unrelated root span. Both IDs/the trace ID are
// generated here since this plugin already knows its own caller/target
// relationship within a single poll; the lineage registry is for OTHER
// plugins with no such local relationship of their own.
func (self *ExternalServiceMonitorPlugin) pollTarget(target ExternalServiceTarget) {
	conns, err := findConnectionsToPort(target.Port)
	if err != nil {
		esmlog.WithError(err).
			WithField("target", target.Name).
			Warn("failed to read /proc/net/tcp")
		return
	}

	for _, c := range conns {
		lookupStart := time.Now()
		pid, comm, found := findPidForInode(c.inode)
		lookupElapsed := time.Since(lookupStart)

		processName := "unknown"
		if found {
			processName = comm
		}

		entry := esmlog.WithField("target", target.Name).
			WithField("caller_local_port", c.localPort).
			WithField("remote_ip", c.remoteIP).
			WithField("inode", c.inode)
		if found {
			entry = entry.WithField("pid", pid).WithField("process", comm)
		}
		entry.Info("external caller connected")

		traceID := randHex(16)
		callerSpanID := randHex(8)
		host := hostName()

		commonAttrs := map[string]interface{}{
			"target.name": target.Name,
			"target.port": target.Port,
			"host.name":   host,
		}

		callerAttrs := map[string]interface{}{
			"caller.local_port": c.localPort,
			"caller.remote_ip":  c.remoteIP,
			"caller.pid":        pid,
			"caller.process":    processName,
			"caller.resolved":   found,
			// net.peer.name/port are New Relic's semantic-convention
			// attributes for classifying this as an External call and
			// indexing it on the External services page (see
			// trace-api-decorate-spans-attributes docs) - purely additive.
			// c.remoteIP is the real, discovered address this caller
			// actually connected to, not a config guess.
			"net.peer.name": c.remoteIP,
			"net.peer.port": target.Port,
		}
		for k, v := range commonAttrs {
			callerAttrs[k] = v
		}

		SubmitSpan(SpanRequest{
			ID:          callerSpanID,
			TraceID:     traceID,
			ServiceName: externalServiceName,
			Name:        "external_service.connected",
			Timestamp:   lookupStart,
			Duration:    lookupElapsed,
			Attributes:  callerAttrs,
		})

		destAttrs := map[string]interface{}{
			"caller.process": processName,
			"caller.pid":     pid,
		}
		for k, v := range commonAttrs {
			destAttrs[k] = v
		}

		// DestinationService lets this reuse an identity that already
		// exists elsewhere (e.g. "kafka-broker-0") instead of minting a new
		// one; falls back to the target's own configured name when unset.
		destServiceName := target.Name
		if target.DestinationService != "" {
			destServiceName = target.DestinationService
		}

		SubmitSpan(SpanRequest{
			ID:          randHex(8),
			TraceID:     traceID,
			ParentID:    callerSpanID,
			ServiceName: destServiceName,
			Name:        target.Name + ".accept",
			Timestamp:   lookupStart.Add(lookupElapsed),
			Duration:    lookupElapsed,
			Attributes:  destAttrs,
		})
	}
}

func (self *ExternalServiceMonitorPlugin) poll() {
	if len(self.targets) == 0 {
		esmlog.Debug("no targets configured, nothing to monitor")
		return
	}
	for _, target := range self.targets {
		self.pollTarget(target)
	}
}

func (self *ExternalServiceMonitorPlugin) Run() {
	refreshTimer := time.NewTicker(1)
	for {
		select {
		case <-refreshTimer.C:
			refreshTimer.Stop()
			refreshTimer = time.NewTicker(self.frequency)
			self.poll()
		}
	}
}

// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"
)

var nginxlog = log.WithPlugin("NginxSpans")

var nginxSpansPluginID = ids.PluginID{"nginx", "spans"}

// ProxyConfig is one TCP proxy hop sitting between an existing caller and an
// existing destination service - nginx's stream module in front of Postgres
// today, any other proxy tomorrow. UpstreamService and CallerService are
// service names that ALREADY exist elsewhere (e.g. "kafka-postgres" from
// DatabaseConfig, "kafka-consumer-jmxspan" from the component with this
// span_role), so the chained span lands on those same nodes instead of
// minting duplicates - the same shared-identity convention as
// brokerServiceName / databaseServiceName, just spelled directly in config
// since there is only one physical caller/destination per proxy hop.
// CallerService is optional: when the real caller into this proxy isn't a
// known, configured component, leave it unset and the discovered caller
// falls back to the one generic externalServiceName instead of fragmenting
// into a per-process identity.
type ProxyConfig struct {
	Name            string `yaml:"name"`
	ListenPort      int    `yaml:"listen_port"`
	UpstreamPort    int    `yaml:"upstream_port"`
	StatusURL       string `yaml:"status_url,omitempty"`
	AttributeLabel  string `yaml:"attribute_label,omitempty"`
	UpstreamService string `yaml:"upstream_service"`
	CallerService   string `yaml:"caller_service,omitempty"`
}

// loadProxyConfigs reads the "proxies" key from the same targets config
// file the other two plugins use. Unmarshalling into a struct that only
// declares Proxies leaves "integrations" (and any other key) untouched, so
// this can't interfere with loadMonitorIntegrations/loadMonitorTargets.
func loadProxyConfigs(path string) ([]ProxyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Proxies []ProxyConfig `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Proxies, nil
}

type NginxSpansPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	proxies   []ProxyConfig
}

func NewNginxSpansPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	proxies, err := loadProxyConfigs(defaultTargetsConfigPath)
	if err != nil {
		nginxlog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no proxies config found or failed to parse; nothing will be monitored until it exists")
	}

	return &NginxSpansPlugin{
		PluginCommon: agent.PluginCommon{ID: nginxSpansPluginID, Context: ctx},
		frequency:    15 * time.Second,
		proxies:      proxies,
	}
}

// queryNginxActiveConnections fetches nginx's stub_status page and parses
// the "Active connections: N" line - the one metric stub_status exposes
// without extra modules.
func queryNginxActiveConnections(url string) (value float64, elapsed time.Duration, err error) {
	start := time.Now()
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	elapsed = time.Since(start)
	if err != nil {
		return 0, elapsed, err
	}

	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "Active connections:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 3 {
			if v, parseErr := strconv.ParseFloat(fields[2], 64); parseErr == nil {
				return v, elapsed, nil
			}
		}
	}
	return 0, elapsed, nil
}

// sendProxyChains discovers real callers into this proxy's listen port and,
// for each one, submits three spans sharing one trace: the caller (root) ->
// this proxy (child) -> the proxy's upstream service (grandchild) - a real
// 3-level chain. UpstreamPort is only used to record whether the proxy's
// own outbound leg was observed this poll; it is not used to pick which
// upstream connection belongs to which caller; there is no way to make
// that link from /proc/net/tcp alone once nginx multiplexes connections,
// so every caller found this poll shares the same proxy-level metric
// snapshot instead. All three IDs/the trace ID are generated here (not via
// SubmitSpan's ParentFrom lookup) because this plugin already knows its
// own internal chain within a single poll - the lineage registry is for
// OTHER plugins with no such local relationship of their own.
func (self *NginxSpansPlugin) sendProxyChains(proxy ProxyConfig) {
	metricValue, metricElapsed, err := queryNginxActiveConnections(proxy.StatusURL)
	if err != nil {
		nginxlog.WithError(err).WithField("proxy", proxy.Name).Warn("failed to query nginx stub_status")
		return
	}

	callerConns, err := findConnectionsToPort(proxy.ListenPort)
	if err != nil {
		nginxlog.WithError(err).WithField("proxy", proxy.Name).Warn("failed to read /proc/net/tcp for proxy listen port")
		return
	}
	if len(callerConns) == 0 {
		nginxlog.WithField("proxy", proxy.Name).Debug("no callers observed into proxy this poll")
		return
	}

	upstreamConns, _ := findConnectionsToPort(proxy.UpstreamPort)
	host := hostName()

	for _, c := range callerConns {
		lookupStart := time.Now()
		pid, comm, found := findPidForInode(c.inode)
		lookupElapsed := time.Since(lookupStart)
		processName := "unknown"
		if found {
			processName = comm
		}

		traceID := randHex(16)
		callerSpanID := randHex(8)
		proxySpanID := randHex(8)
		now := time.Now()

		callerServiceName := externalServiceName
		if proxy.CallerService != "" {
			callerServiceName = proxy.CallerService
		}

		// net.peer.name/port are New Relic's semantic-convention attributes
		// for classifying a span as an External call and indexing it on
		// the External services page (see trace-api-decorate-spans-
		// attributes docs) - purely additive, no effect on span identity
		// or chaining. c.remoteIP is the real, discovered address this
		// caller actually connected to, not a config guess.
		upstreamPeerName := "unknown"
		if len(upstreamConns) > 0 {
			upstreamPeerName = upstreamConns[0].remoteIP
		}

		SubmitSpan(SpanRequest{
			ID:          callerSpanID,
			TraceID:     traceID,
			ServiceName: callerServiceName,
			Name:        proxy.Name + ".connect",
			Timestamp:   lookupStart,
			Duration:    lookupElapsed,
			Attributes: map[string]interface{}{
				"host.name":         host,
				"caller.local_port": c.localPort,
				"caller.remote_ip":  c.remoteIP,
				"caller.pid":        pid,
				"caller.process":    processName,
				"proxy.name":        proxy.Name,
				"net.peer.name":     c.remoteIP,
				"net.peer.port":     proxy.ListenPort,
			},
		})

		SubmitSpan(SpanRequest{
			ID:          proxySpanID,
			TraceID:     traceID,
			ParentID:    callerSpanID,
			ServiceName: proxy.Name,
			Name:        proxy.Name + ".proxy",
			Timestamp:   now,
			Duration:    metricElapsed,
			Attributes: map[string]interface{}{
				"host.name":               host,
				"proxy.listen_port":       proxy.ListenPort,
				"proxy.upstream_port":     proxy.UpstreamPort,
				"proxy.upstream_observed": len(upstreamConns) > 0,
				proxy.AttributeLabel:      metricValue,
				"net.peer.name":           upstreamPeerName,
				"net.peer.port":           proxy.UpstreamPort,
			},
		})

		SubmitSpan(SpanRequest{
			ID:          randHex(8),
			TraceID:     traceID,
			ParentID:    proxySpanID,
			ServiceName: proxy.UpstreamService,
			Name:        proxy.Name + ".upstream",
			Timestamp:   now.Add(metricElapsed),
			// A zero Duration makes the SDK omit "duration.ms" entirely
			// (see telemetryapi/spans.go), which the Trace API then silently
			// drops the span for - no client-side error, since it's a
			// per-item ingest rejection inside an otherwise-200 batch. There
			// is no independently measured latency for this hop, so reuse
			// the one real elapsed value already on hand.
			Duration: metricElapsed,
			Attributes: map[string]interface{}{
				"host.name":  host,
				"proxy.name": proxy.Name,
			},
		})

		nginxlog.WithField("trace_id", traceID).
			WithField("proxy", proxy.Name).
			WithField("caller_process", processName).
			WithField("metric", metricValue).
			Info("sent real chained proxy span (caller -> proxy -> upstream)")
	}
}

func (self *NginxSpansPlugin) poll() {
	if len(self.proxies) == 0 {
		nginxlog.Debug("no proxies configured, nothing to send")
		return
	}
	for _, proxy := range self.proxies {
		self.sendProxyChains(proxy)
	}
}

func (self *NginxSpansPlugin) Run() {
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

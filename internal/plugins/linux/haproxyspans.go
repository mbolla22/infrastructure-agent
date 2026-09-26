// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"
)

var haproxylog = log.WithPlugin("HAProxySpans")

var haproxySpansPluginID = ids.PluginID{"haproxy", "spans"}

// HAProxyConfig is one HAProxy TCP-passthrough hop, structurally similar to
// nginxspans.go's ProxyConfig but reading its own "haproxies" config key and
// querying HAProxy's own CSV stats format - kept in its own file for the
// same reason kafka/nginx/postgres each have theirs: the status-query logic
// is genuinely different per proxy technology, even though the chain shape
// (caller -> proxy -> upstream) is the same.
//
// Unlike nginx's persistent stream-proxied connections, a bootstrap-only
// hop like this one (a Kafka client dials the proxy once at startup, then
// reconnects directly to the broker's real advertised address for all
// further traffic) is too brief to reliably catch as a live connection via
// /proc/net/tcp polling. HAProxy's own "stot" (total sessions, a
// monotonically increasing counter) still records it even after the
// connection closes, so this plugin detects activity by that counter's
// delta between polls instead of requiring a live connection at poll time.
type HAProxyConfig struct {
	Name            string `yaml:"name"`
	ListenPort      int    `yaml:"listen_port"`
	StatsURL        string `yaml:"stats_url"`
	BackendName     string `yaml:"backend_name"`
	UpstreamService string `yaml:"upstream_service"`
	CallerService   string `yaml:"caller_service,omitempty"`
}

type haproxyTargetsFile struct {
	HAProxies []HAProxyConfig `yaml:"haproxies"`
}

func loadHAProxyConfigs(path string) ([]HAProxyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f haproxyTargetsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.HAProxies, nil
}

// queryHAProxyStats fetches HAProxy's CSV stats page and returns the
// cumulative session count (stot) and current session count (scur) for the
// BACKEND aggregate row of the named backend. Column positions are read
// from the CSV's own header row rather than hardcoded, since they vary
// across HAProxy versions.
func queryHAProxyStats(statsURL, backendName string) (stot, scur int64, elapsed time.Duration, err error) {
	start := time.Now()
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(statsURL)
	if err != nil {
		return 0, 0, time.Since(start), err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	elapsed = time.Since(start)
	if err != nil {
		return 0, 0, elapsed, err
	}

	lines := strings.Split(string(body), "\n")
	if len(lines) < 2 {
		return 0, 0, elapsed, fmt.Errorf("haproxy stats response too short")
	}

	header := strings.Split(strings.TrimPrefix(strings.TrimSpace(lines[0]), "# "), ",")
	col := make(map[string]int, len(header))
	for i, h := range header {
		col[h] = i
	}
	pxIdx, pxOK := col["pxname"]
	svIdx, svOK := col["svname"]
	stotIdx, stotOK := col["stot"]
	scurIdx, scurOK := col["scur"]
	if !pxOK || !svOK || !stotOK || !scurOK {
		return 0, 0, elapsed, fmt.Errorf("haproxy stats missing expected columns")
	}

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) <= svIdx || fields[pxIdx] != backendName || fields[svIdx] != "BACKEND" {
			continue
		}
		stotVal, _ := strconv.ParseInt(fields[stotIdx], 10, 64)
		scurVal, _ := strconv.ParseInt(fields[scurIdx], 10, 64)
		return stotVal, scurVal, elapsed, nil
	}
	return 0, 0, elapsed, fmt.Errorf("backend %q not found in haproxy stats", backendName)
}

type HAProxySpansPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	proxies   []HAProxyConfig

	mu       sync.Mutex
	lastStot map[string]int64
}

func NewHAProxySpansPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	proxies, err := loadHAProxyConfigs(defaultTargetsConfigPath)
	if err != nil {
		haproxylog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no haproxy targets config found or failed to parse; nothing will be monitored until it exists")
	}

	return &HAProxySpansPlugin{
		PluginCommon: agent.PluginCommon{ID: haproxySpansPluginID, Context: ctx},
		frequency:    10 * time.Second,
		proxies:      proxies,
		lastStot:     make(map[string]int64),
	}
}

// sendHAProxyChain queries this proxy's real session counter and, if it has
// increased since the last poll, submits a caller -> proxy -> upstream
// chain for the sessions that happened in between - even though those
// connections are very likely already closed by the time we poll. PID/
// process attribution is best-effort only: if a connection into ListenPort
// happens to still be live at poll time we attach it, but the span is sent
// either way since CallerService already gives it a known identity.
func (self *HAProxySpansPlugin) sendHAProxyChain(proxy HAProxyConfig) {
	stot, scur, elapsed, err := queryHAProxyStats(proxy.StatsURL, proxy.BackendName)
	if err != nil {
		haproxylog.WithError(err).WithField("proxy", proxy.Name).Warn("failed to query haproxy stats")
		return
	}

	self.mu.Lock()
	prev, seen := self.lastStot[proxy.Name]
	self.lastStot[proxy.Name] = stot
	self.mu.Unlock()

	if !seen {
		haproxylog.WithField("proxy", proxy.Name).Debug("first poll, recording baseline session count")
		return
	}
	delta := stot - prev
	if delta <= 0 {
		haproxylog.WithField("proxy", proxy.Name).Debug("no new haproxy sessions since last poll")
		return
	}

	pid, processName, resolved := 0, "unknown", false
	if conns, cerr := findConnectionsToPort(proxy.ListenPort); cerr == nil && len(conns) > 0 {
		if p, comm, ok := findPidForInode(conns[0].inode); ok {
			pid, processName, resolved = p, comm, true
		}
	}

	traceID := randHex(16)
	callerSpanID := randHex(8)
	proxySpanID := randHex(8)
	now := time.Now()
	host := hostName()

	callerServiceName := externalServiceName
	if proxy.CallerService != "" {
		callerServiceName = proxy.CallerService
	}

	SubmitSpan(SpanRequest{
		ID:          callerSpanID,
		TraceID:     traceID,
		ServiceName: callerServiceName,
		Name:        proxy.Name + ".connect",
		Timestamp:   now,
		Duration:    elapsed,
		Attributes: map[string]interface{}{
			"host.name":            host,
			"proxy.name":           proxy.Name,
			"caller.pid":           pid,
			"caller.process":       processName,
			"caller.resolved":      resolved,
			"haproxy.new_sessions": delta,
		},
	})

	SubmitSpan(SpanRequest{
		ID:          proxySpanID,
		TraceID:     traceID,
		ParentID:    callerSpanID,
		ServiceName: proxy.Name,
		Name:        proxy.Name + ".proxy",
		Timestamp:   now,
		Duration:    elapsed,
		Attributes: map[string]interface{}{
			"host.name":                host,
			"haproxy.total_sessions":   stot,
			"haproxy.current_sessions": scur,
			"haproxy.new_sessions":     delta,
		},
	})

	SubmitSpan(SpanRequest{
		ID:          randHex(8),
		TraceID:     traceID,
		ParentID:    proxySpanID,
		ServiceName: proxy.UpstreamService,
		Name:        proxy.Name + ".upstream",
		Timestamp:   now,
		Duration:    elapsed,
		Attributes: map[string]interface{}{
			"host.name": host,
		},
	})

	haproxylog.WithField("trace_id", traceID).
		WithField("proxy", proxy.Name).
		WithField("new_sessions", delta).
		WithField("caller_resolved", resolved).
		Info("sent real haproxy-derived span chain for sessions since last poll")
}

func (self *HAProxySpansPlugin) poll() {
	if len(self.proxies) == 0 {
		haproxylog.Debug("no haproxy targets configured, nothing to send")
		return
	}
	for _, proxy := range self.proxies {
		self.sendHAProxyChain(proxy)
	}
}

func (self *HAProxySpansPlugin) Run() {
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

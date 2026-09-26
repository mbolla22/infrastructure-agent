// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"
)

var eslog = log.WithPlugin("ElasticsearchSpans")

var elasticsearchSpansPluginID = ids.PluginID{"elasticsearch", "spans"}

// ElasticsearchConfig is a real document-count query against Elasticsearch's
// own REST API - the one piece of Elasticsearch-specific monitoring logic
// in this agent, kept in its own file for the same reason kafka's JMX logic
// lives in kafkaspans.go and Postgres's SQL logic lives in postgresspans.go.
type ElasticsearchConfig struct {
	CountURL       string `yaml:"count_url"`
	AttributeLabel string `yaml:"attribute_label"`
}

// ElasticsearchTarget is one index to monitor: its own identity
// (ServiceName), the query that produces its one real metric, and -
// optionally - ParentService, the name of a service another plugin has
// already submitted a span for that this target's span should chain onto
// via SubmitSpan's ParentFrom, instead of starting an unlinked root every
// time - same convention as PostgresTarget.
type ElasticsearchTarget struct {
	Name          string               `yaml:"name"`
	ServiceName   string               `yaml:"service_name"`
	ES            *ElasticsearchConfig `yaml:"es,omitempty"`
	ParentService string               `yaml:"parent_service,omitempty"`
}

type elasticsearchTargetsFile struct {
	Indices []ElasticsearchTarget `yaml:"elasticsearch_indices"`
}

// loadElasticsearchTargets reads the "elasticsearch_indices" key from the
// same targets config file the other plugins use. Unmarshalling into a
// struct that only declares Indices leaves every other top-level key
// untouched, so this can't interfere with the other plugins' own loaders.
func loadElasticsearchTargets(path string) ([]ElasticsearchTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f elasticsearchTargetsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Indices, nil
}

// esCountResponse matches Elasticsearch's _count API response shape:
// {"count": N, "_shards": {...}}. Only count is needed here.
type esCountResponse struct {
	Count float64 `json:"count"`
}

// queryElasticsearchCount hits an index's _count endpoint and returns the
// real document count plus how long the round trip took. Opened fresh each
// call, same non-pooled, poll-cycle-scoped pattern used for JMX, stub_status,
// and Postgres.
func queryElasticsearchCount(es *ElasticsearchConfig) (value float64, elapsed time.Duration, err error) {
	start := time.Now()
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(es.CountURL)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()

	var parsed esCountResponse
	decodeErr := json.NewDecoder(resp.Body).Decode(&parsed)
	elapsed = time.Since(start)
	if decodeErr != nil {
		return 0, elapsed, decodeErr
	}
	return parsed.Count, elapsed, nil
}

type ElasticsearchSpansPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	targets   []ElasticsearchTarget
}

func NewElasticsearchSpansPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	targets, err := loadElasticsearchTargets(defaultTargetsConfigPath)
	if err != nil {
		eslog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no elasticsearch targets config found or failed to parse; nothing will be monitored until it exists")
	}

	return &ElasticsearchSpansPlugin{
		PluginCommon: agent.PluginCommon{ID: elasticsearchSpansPluginID, Context: ctx},
		frequency:    30 * time.Second,
		targets:      targets,
	}
}

// sendElasticsearchSpan queries one index's real document count and submits
// a span under its ServiceName. Like Postgres, Elasticsearch never
// initiates a call to anyone - it is purely a server - so this plugin has
// no caller of its own to chain onto directly. When ParentService is
// configured, SubmitSpan's ParentFrom looks up whichever OTHER plugin most
// recently submitted a span for that name (e.g. kafkaspans.go's
// "kafka-consumer-jmxspan" span) and chains onto it.
func (self *ElasticsearchSpansPlugin) sendElasticsearchSpan(target ElasticsearchTarget) {
	if target.ES == nil {
		eslog.WithField("index", target.Name).Debug("no es block configured, nothing to query")
		return
	}

	value, elapsed, err := queryElasticsearchCount(target.ES)
	if err != nil {
		eslog.WithError(err).WithField("index", target.Name).Warn("failed to query elasticsearch count")
		return
	}

	SubmitSpan(SpanRequest{
		ServiceName: target.ServiceName,
		Name:        "elasticsearch.health_check",
		Timestamp:   time.Now(),
		Duration:    elapsed,
		ParentFrom:  target.ParentService,
		Attributes: map[string]interface{}{
			"host.name":              hostName(),
			"index.name":             target.Name,
			"db.system":              "elasticsearch",
			target.ES.AttributeLabel: value,
		},
	})

	eslog.WithField("index", target.Name).
		WithField("service", target.ServiceName).
		WithField("metric", value).
		Info("sent real elasticsearch self-report span")
}

func (self *ElasticsearchSpansPlugin) poll() {
	if len(self.targets) == 0 {
		eslog.Debug("no elasticsearch targets configured, nothing to monitor")
		return
	}
	for _, target := range self.targets {
		self.sendElasticsearchSpan(target)
	}
}

func (self *ElasticsearchSpansPlugin) Run() {
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

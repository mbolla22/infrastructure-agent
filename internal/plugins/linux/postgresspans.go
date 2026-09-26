// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"database/sql"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"

	_ "github.com/lib/pq"
)

var pglog = log.WithPlugin("PostgresSpans")

var postgresSpansPluginID = ids.PluginID{"postgres", "spans"}

// PostgresConfig is a real SQL metric queried directly against Postgres -
// the one piece of Postgres-specific monitoring logic in this agent, kept
// in its own file for the same reason kafka's JMX logic lives in
// kafkaspans.go and nginx's stub_status logic lives in nginxspans.go. DSN
// should point through nginx's proxy port when a proxy sits in front of
// this database, not at Postgres directly, so the query itself - not just
// any span naming - still respects the real network path.
type PostgresConfig struct {
	Driver         string `yaml:"driver"`
	DSN            string `yaml:"dsn"`
	Query          string `yaml:"query"`
	AttributeLabel string `yaml:"attribute_label"`
}

// PostgresTarget is one database to monitor: its own identity (ServiceName),
// the query that produces its one real metric, and - optionally -
// ParentService, the name of a service another plugin has already
// submitted a span for (e.g. "nginx-postgres") that this target's span
// should chain onto via SubmitSpan's ParentFrom, instead of starting an
// unlinked root every time.
type PostgresTarget struct {
	Name          string          `yaml:"name"`
	ServiceName   string          `yaml:"service_name"`
	SQL           *PostgresConfig `yaml:"sql,omitempty"`
	ParentService string          `yaml:"parent_service,omitempty"`
}

type postgresTargetsFile struct {
	Databases []PostgresTarget `yaml:"databases"`
}

// loadPostgresTargets reads the "databases" key from the same targets
// config file the other plugins use. Unmarshalling into a struct that only
// declares Databases leaves "integrations"/"proxies"/"external_services"
// untouched, so this can't interfere with the other plugins' own loaders.
func loadPostgresTargets(path string) ([]PostgresTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f postgresTargetsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Databases, nil
}

// queryPostgresMetric runs a single query expected to return one numeric
// column in its first row, and returns that value plus how long the round
// trip took. Opened and closed once per call, same non-pooled,
// poll-cycle-scoped pattern used for JMX and nginx's stub_status.
func queryPostgresMetric(pg *PostgresConfig) (value float64, elapsed time.Duration, err error) {
	start := time.Now()

	db, err := sql.Open(pg.Driver, pg.DSN)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer db.Close()

	err = db.QueryRow(pg.Query).Scan(&value)
	elapsed = time.Since(start)
	if err != nil {
		return 0, elapsed, err
	}
	return value, elapsed, nil
}

type PostgresSpansPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	targets   []PostgresTarget
}

func NewPostgresSpansPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	targets, err := loadPostgresTargets(defaultTargetsConfigPath)
	if err != nil {
		pglog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no postgres targets config found or failed to parse; nothing will be monitored until it exists")
	}

	return &PostgresSpansPlugin{
		PluginCommon: agent.PluginCommon{ID: postgresSpansPluginID, Context: ctx},
		frequency:    30 * time.Second,
		targets:      targets,
	}
}

// sendPostgresSpan queries one database's real metric and submits a span
// under its ServiceName. Postgres itself never initiates a call to anyone;
// it is purely a server, so this plugin has no caller of its own to chain
// onto directly. Instead, when ParentService is configured, SubmitSpan's
// ParentFrom looks up whichever OTHER plugin most recently submitted a
// span for that name (e.g. nginxspans.go's "nginx-postgres" span) and
// chains onto it - the real metric ends up on the same trace nginx's chain
// already builds, instead of a second, disconnected "caller -> postgres"
// edge duplicating that relationship.
func (self *PostgresSpansPlugin) sendPostgresSpan(target PostgresTarget) {
	if target.SQL == nil {
		pglog.WithField("database", target.Name).Debug("no sql block configured, nothing to query")
		return
	}

	value, elapsed, err := queryPostgresMetric(target.SQL)
	if err != nil {
		pglog.WithError(err).WithField("database", target.Name).Warn("failed to query postgres metric")
		return
	}

	SubmitSpan(SpanRequest{
		ServiceName: target.ServiceName,
		Name:        "postgres.health_check",
		Timestamp:   time.Now(),
		Duration:    elapsed,
		ParentFrom:  target.ParentService,
		Attributes: map[string]interface{}{
			"host.name":     hostName(),
			"database.name": target.Name,
			// db.* are New Relic's semantic-convention attributes for
			// classifying this as a Datastore span, including on the
			// dedicated Databases page (see trace-api-decorate-spans-
			// attributes docs) - purely additive, this file is already
			// Postgres-specific so hardcoding "postgresql" here is
			// accurate, unlike the generic nginxspans.go/kafkaspans.go.
			"db.system":               "postgresql",
			"db.statement":            target.SQL.Query,
			target.SQL.AttributeLabel: value,
		},
	})

	pglog.WithField("database", target.Name).
		WithField("service", target.ServiceName).
		WithField("metric", value).
		Info("sent real postgres self-report span")
}

func (self *PostgresSpansPlugin) poll() {
	if len(self.targets) == 0 {
		pglog.Debug("no postgres targets configured, nothing to monitor")
		return
	}
	for _, target := range self.targets {
		self.sendPostgresSpan(target)
	}
}

func (self *PostgresSpansPlugin) Run() {
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

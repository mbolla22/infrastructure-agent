// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/log"
	"github.com/newrelic/infrastructure-agent/pkg/plugins/ids"
	"github.com/newrelic/nrjmx/gojmx"

	_ "github.com/lib/pq"
)

var kslog = log.WithPlugin("KafkaSpans")

var kafkaSpansPluginID = ids.PluginID{"jmx", "spans"}

func hostName() string {
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		if fqdn := strings.TrimSpace(string(out)); fqdn != "" {
			return fqdn
		}
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

// randHex is the one random-ID generator shared by every span-producing
// plugin in this package - span/trace IDs need no more than this.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// jmxSpanPair is one caller-side component paired with ONE of its
// integration's brokers, both carrying the JMX details needed to query them.
// A client component is paired against every configured broker separately -
// a real Kafka client can reach any broker (whichever is the partition
// leader), so there is no single fixed "the broker" to pick once there is
// more than one; each poll cycle produces one linked pair per broker.
type jmxSpanPair struct {
	integrationName string
	clusterName     string
	topic           string
	client          MonitorComponent
	broker          BrokerConfig
}

// dbSpanPair is one consumer paired with its integration's downstream
// database, mirroring jmxSpanPair's client/broker pairing but for the
// consumer -> database hop instead of the client -> broker hop.
type dbSpanPair struct {
	integrationName string
	clusterName     string
	consumer        MonitorComponent
	database        DatabaseConfig
}

type KafkaSpansPlugin struct {
	agent.PluginCommon
	frequency time.Duration
	pairs     []jmxSpanPair
	dbPairs   []dbSpanPair
}

// buildJMXSpanPairs walks the configured integrations and pairs every
// component with a span_role (producer/consumer/...) against EVERY broker
// configured for that integration - not just one. Components or brokers with
// no JMX block are skipped.
func buildJMXSpanPairs(integrations []MonitorIntegration) []jmxSpanPair {
	var pairs []jmxSpanPair
	for _, integration := range integrations {
		var brokersWithJMX []BrokerConfig
		for _, broker := range integration.Brokers {
			if broker.JMX != nil {
				brokersWithJMX = append(brokersWithJMX, broker)
			}
		}
		if len(brokersWithJMX) == 0 {
			continue
		}
		for _, component := range integration.Components {
			if component.SpanRole == "" || component.JMX == nil {
				continue
			}
			for _, broker := range brokersWithJMX {
				pairs = append(pairs, jmxSpanPair{
					integrationName: integration.Name,
					clusterName:     integration.ClusterName,
					topic:           integration.Topic,
					client:          component,
					broker:          broker,
				})
			}
		}
	}
	return pairs
}

// buildDBSpanPairs pairs every "consumer" span-role component against its
// integration's database, when both a database and a SQL block are
// configured. A database sits downstream of the consumer only - there is no
// producer/database or broker/database pairing, since that's not how the
// data actually flows.
func buildDBSpanPairs(integrations []MonitorIntegration) []dbSpanPair {
	var pairs []dbSpanPair
	for _, integration := range integrations {
		if integration.Database == nil || integration.Database.SQL == nil {
			continue
		}
		for _, component := range integration.Components {
			if component.SpanRole != "consumer" || component.JMX == nil {
				continue
			}
			pairs = append(pairs, dbSpanPair{
				integrationName: integration.Name,
				clusterName:     integration.ClusterName,
				consumer:        component,
				database:        *integration.Database,
			})
		}
	}
	return pairs
}

func NewKafkaSpansPlugin(ctx agent.AgentContext) agent.Plugin {
	ensureHarvester(ctx)

	integrations, err := loadMonitorIntegrations(defaultTargetsConfigPath)
	if err != nil {
		kslog.WithError(err).WithField("path", defaultTargetsConfigPath).
			Warn("no external-service-monitor config found or failed to parse; nothing will be monitored until it exists")
	}

	return &KafkaSpansPlugin{
		PluginCommon: agent.PluginCommon{ID: kafkaSpansPluginID, Context: ctx},
		frequency:    30 * time.Second,
		pairs:        buildJMXSpanPairs(integrations),
		dbPairs:      buildDBSpanPairs(integrations),
	}
}

// queryOneAttr opens a JMX connection to the given host/port, queries a
// single named MBean attribute, and returns its numeric value plus how long
// the query took.
func queryOneAttr(host string, port int32, mBean, attrName string) (value float64, elapsed time.Duration, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := gojmx.NewClient(ctx)
	start := time.Now()

	conn, err := client.Open(&gojmx.JMXConfig{
		Hostname:         host,
		Port:             port,
		RequestTimeoutMs: 5000,
	})
	if err != nil {
		return 0, time.Since(start), err
	}
	defer conn.Close()

	attrs, err := conn.QueryMBeanAttributes(mBean, attrName)
	elapsed = time.Since(start)
	if err != nil {
		return 0, elapsed, err
	}

	for _, a := range attrs {
		if a.ResponseType != gojmx.ResponseTypeErr {
			return a.DoubleValue, elapsed, nil
		}
	}
	return 0, elapsed, nil
}

// querySQLValue opens a connection to the given database, runs a single
// query expected to return one numeric column in its first row, and returns
// that value plus how long the round trip took. Opened and closed once per
// call, same non-pooled, poll-cycle-scoped pattern as queryOneAttr's JMX
// connection.
func querySQLValue(sm *SQLMetric) (value float64, elapsed time.Duration, err error) {
	start := time.Now()

	db, err := sql.Open(sm.Driver, sm.DSN)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer db.Close()

	err = db.QueryRow(sm.Query).Scan(&value)
	elapsed = time.Since(start)
	if err != nil {
		return 0, elapsed, err
	}
	return value, elapsed, nil
}

// sendLinkedPair queries one client-side component and one specific broker,
// then submits two spans: client (parent/caller) -> that broker (child/
// server), sharing a fresh trace ID for this poll cycle. Called once per
// (client component, broker) combination, so with N brokers a given client
// gets N independent pairs per poll - see jmxSpanPair's doc comment for why.
// Both IDs/the trace ID are generated here (not via SubmitSpan's
// ParentFrom lookup) because this plugin already knows its own internal
// chain within a single poll.
func (self *KafkaSpansPlugin) sendLinkedPair(pair jmxSpanPair) {
	clientJMX := pair.client.JMX
	brokerJMX := pair.broker.JMX

	clientValue, clientElapsed, err := queryOneAttr(clientJMX.hostOrDefault(), int32(clientJMX.Port), clientJMX.Bean, clientJMX.Attribute)
	if err != nil {
		kslog.WithError(err).WithField("integration", pair.integrationName).
			WithField("component", pair.client.Name).Warn("failed to query client JMX metric")
		return
	}

	brokerValue, brokerElapsed, err := queryOneAttr(brokerJMX.hostOrDefault(), int32(brokerJMX.Port), brokerJMX.Bean, brokerJMX.Attribute)
	if err != nil {
		kslog.WithError(err).WithField("integration", pair.integrationName).
			WithField("broker_id", pair.broker.BrokerID).Warn("failed to query broker JMX metric")
		return
	}

	traceID := randHex(16)
	clientSpanID := randHex(8)
	now := time.Now()
	host := hostName()

	clientServiceName := pair.integrationName + "-" + pair.client.Name + "-jmxspan"
	// Shared with external/service_monitor's own broker spans (see
	// brokerServiceName's doc comment) so both plugins agree on this
	// broker's identity instead of minting two unrelated names for it.
	brokerSvcName := brokerServiceName(pair.integrationName, pair.broker.BrokerID)

	clientAttrs := map[string]interface{}{
		"integration.name":       pair.integrationName,
		"kafka.cluster.name":     pair.clusterName,
		"component.name":         pair.client.Name,
		"span.kind":              pair.client.SpanRole,
		"host.name":              host,
		"broker.id":              pair.broker.BrokerID,
		clientJMX.AttributeLabel: clientValue,
		// net.peer.name/port are New Relic's semantic-convention attributes
		// for classifying this as an External span and indexing it on the
		// External services page (see trace-api-decorate-spans-attributes
		// docs) - purely additive, no effect on span identity or chaining.
		"net.peer.name": brokerJMX.hostOrDefault(),
		"net.peer.port": brokerJMX.Port,
	}
	// Additive: only queried/added when this component has a topic_jmx
	// block configured. Absent config -> absent attribute, no behavior
	// change from before this existed.
	if pair.client.TopicJMX != nil {
		tj := pair.client.TopicJMX
		if v, _, err := queryOneAttr(tj.hostOrDefault(), int32(tj.Port), tj.Bean, tj.Attribute); err != nil {
			kslog.WithError(err).WithField("integration", pair.integrationName).
				WithField("component", pair.client.Name).Warn("failed to query client per-topic JMX metric")
		} else {
			clientAttrs["messaging.destination.name"] = pair.topic
			clientAttrs[tj.AttributeLabel] = v
		}
	}

	brokerAttrs := map[string]interface{}{
		"integration.name":       pair.integrationName,
		"kafka.cluster.name":     pair.clusterName,
		"component.name":         "broker",
		"broker.id":              pair.broker.BrokerID,
		"span.kind":              "server",
		"host.name":              host,
		brokerJMX.AttributeLabel: brokerValue,
	}
	if pair.broker.TopicJMX != nil {
		tj := pair.broker.TopicJMX
		if v, _, err := queryOneAttr(tj.hostOrDefault(), int32(tj.Port), tj.Bean, tj.Attribute); err != nil {
			kslog.WithError(err).WithField("integration", pair.integrationName).
				WithField("broker_id", pair.broker.BrokerID).Warn("failed to query broker per-topic JMX metric")
		} else {
			brokerAttrs["messaging.destination.name"] = pair.topic
			brokerAttrs[tj.AttributeLabel] = v
		}
	}

	SubmitSpan(SpanRequest{
		ID:          clientSpanID,
		TraceID:     traceID,
		ServiceName: clientServiceName,
		Name:        pair.integrationName + "." + pair.client.SpanRole,
		Timestamp:   now,
		Duration:    clientElapsed,
		Attributes:  clientAttrs,
	})

	SubmitSpan(SpanRequest{
		ID:          randHex(8),
		TraceID:     traceID,
		ParentID:    clientSpanID,
		ServiceName: brokerSvcName,
		Name:        pair.integrationName + ".broker.handle",
		Timestamp:   now.Add(clientElapsed),
		Duration:    brokerElapsed,
		Attributes:  brokerAttrs,
	})

	kslog.WithField("trace_id", traceID).
		WithField("service", clientServiceName).
		WithField("broker_id", pair.broker.BrokerID).
		WithField("client_metric", clientValue).
		WithField("broker_metric", brokerValue).
		Info("sent real jmx-derived span pair")
}

// sendDBLinkedPair queries one consumer's JMX metric and its integration's
// database SQL metric, then submits two spans: consumer (parent/caller) ->
// database (child/server), sharing a fresh trace ID for this poll cycle -
// the same linked-pair shape as sendLinkedPair, just with a SQL query
// standing in for the destination's JMX query.
func (self *KafkaSpansPlugin) sendDBLinkedPair(pair dbSpanPair) {
	consumerJMX := pair.consumer.JMX
	dbSQL := pair.database.SQL

	consumerValue, consumerElapsed, err := queryOneAttr(consumerJMX.hostOrDefault(), int32(consumerJMX.Port), consumerJMX.Bean, consumerJMX.Attribute)
	if err != nil {
		kslog.WithError(err).WithField("integration", pair.integrationName).
			WithField("component", pair.consumer.Name).Warn("failed to query consumer JMX metric")
		return
	}

	dbValue, dbElapsed, err := querySQLValue(dbSQL)
	if err != nil {
		kslog.WithError(err).WithField("integration", pair.integrationName).
			WithField("database", pair.database.Name).Warn("failed to query database SQL metric")
		return
	}

	traceID := randHex(16)
	consumerSpanID := randHex(8)
	now := time.Now()
	host := hostName()

	consumerServiceName := pair.integrationName + "-" + pair.consumer.Name + "-jmxspan"
	// Shared with external/service_monitor's own database spans (see
	// databaseServiceName's doc comment) so both plugins agree on this
	// database's identity instead of minting two unrelated names for it.
	dbServiceName := databaseServiceName(pair.integrationName, pair.database.Name)

	consumerAttrs := map[string]interface{}{
		"integration.name":         pair.integrationName,
		"kafka.cluster.name":       pair.clusterName,
		"component.name":           pair.consumer.Name,
		"span.kind":                pair.consumer.SpanRole,
		"host.name":                host,
		consumerJMX.AttributeLabel: consumerValue,
	}

	dbAttrs := map[string]interface{}{
		"integration.name":   pair.integrationName,
		"kafka.cluster.name": pair.clusterName,
		"component.name":     pair.database.Name,
		"span.kind":          "server",
		"host.name":          host,
		dbSQL.AttributeLabel: dbValue,
	}

	SubmitSpan(SpanRequest{
		ID:          consumerSpanID,
		TraceID:     traceID,
		ServiceName: consumerServiceName,
		Name:        pair.integrationName + "." + pair.consumer.SpanRole,
		Timestamp:   now,
		Duration:    consumerElapsed,
		Attributes:  consumerAttrs,
	})

	SubmitSpan(SpanRequest{
		ID:          randHex(8),
		TraceID:     traceID,
		ParentID:    consumerSpanID,
		ServiceName: dbServiceName,
		Name:        pair.integrationName + "." + pair.database.Name + ".write",
		Timestamp:   now.Add(consumerElapsed),
		Duration:    dbElapsed,
		Attributes:  dbAttrs,
	})

	kslog.WithField("trace_id", traceID).
		WithField("service", dbServiceName).
		WithField("consumer_metric", consumerValue).
		WithField("db_metric", dbValue).
		Info("sent real consumer->database span pair")
}

func (self *KafkaSpansPlugin) poll() {
	if len(self.pairs) == 0 && len(self.dbPairs) == 0 {
		kslog.Debug("no span pairs configured, nothing to send")
		return
	}
	for _, pair := range self.pairs {
		self.sendLinkedPair(pair)
	}
	for _, pair := range self.dbPairs {
		self.sendDBLinkedPair(pair)
	}
}

func (self *KafkaSpansPlugin) Run() {
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

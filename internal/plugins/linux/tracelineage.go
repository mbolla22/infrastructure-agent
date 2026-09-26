// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//go:build linux
// +build linux

package linux

import (
	"os"
	"sync"
	"time"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/backend/telemetryapi"
	"github.com/newrelic/infrastructure-agent/pkg/log"
)

// This file is the ONE thing every span-producing plugin (kafkaspans.go,
// nginxspans.go, postgresspans.go, externalservicemonitor.go, and any
// integration added later) feeds into, and the only place that actually
// talks to the Trace API. Each plugin still independently decides what to
// measure and when - JMX polling, stub_status, SQL queries, /proc/net/tcp
// discovery, on each plugin's own schedule - but instead of building a
// telemetryapi.Span and a harvester itself, it hands a SpanRequest to
// SubmitSpan, which:
//  1. resolves the request's TraceID/ParentID - explicit values the caller
//     already knows (e.g. a caller/broker pair built in one function call),
//     a lookup by another service's most recently submitted span (for a
//     plugin with no locally-known parent, e.g. postgresspans.go's
//     self-report), or an intentionally unlinked root, in that order;
//  2. sends the span through the one shared harvester;
//  3. publishes it into the registry so the NEXT plugin can chain onto it.
//
// It is a *lookup*, not an *inference engine*: nothing here guesses which
// spans belong together. A plugin has to explicitly say, via ParentFrom (or
// its own config, e.g. PostgresTarget.ParentService), which already-
// published service name it wants to chain onto.

var tlLog = log.WithPlugin("TraceLineage")

var (
	harvesterOnce   sync.Once
	sharedHarvester *telemetryapi.Harvester
)

// ensureHarvester lazily creates the one shared harvester the first time
// any plugin is constructed - idempotent, so every NewXXXPlugin can call it
// unconditionally regardless of registration order.
func ensureHarvester(ctx agent.AgentContext) *telemetryapi.Harvester {
	harvesterOnce.Do(func() {
		cfg := ctx.Config()
		h, err := telemetryapi.NewHarvester(
			telemetryapi.ConfigAPIKey(cfg.License),
			telemetryapi.ConfigSpansURLOverride("https://staging-trace-api.newrelic.com/trace/v1"),
			telemetryapi.ConfigBasicErrorLogger(os.Stderr),
		)
		if err != nil {
			tlLog.WithError(err).Error("unable to create shared telemetryapi harvester")
			return
		}
		sharedHarvester = h
	})
	return sharedHarvester
}

type publishedSpan struct {
	spanID    string
	traceID   string
	timestamp time.Time
}

var (
	lineageMu        sync.Mutex
	lineageByService = map[string]publishedSpan{}
)

// publishSpan records span as the latest one sent for its service name,
// making it available for a later SubmitSpan's ParentFrom to chain onto.
func publishSpan(span telemetryapi.Span) {
	lineageMu.Lock()
	defer lineageMu.Unlock()
	lineageByService[span.ServiceName] = publishedSpan{
		spanID:    span.ID,
		traceID:   span.TraceID,
		timestamp: time.Now(),
	}
}

// lookupParent returns the most recently published span for serviceName, if
// one was published within maxAge. A miss (nothing published, or too
// stale) is a normal, expected outcome - e.g. the upstream plugin's last
// poll found no live caller to report - and SubmitSpan falls back to an
// unlinked root rather than treating it as an error.
func lookupParent(serviceName string, maxAge time.Duration) (spanID, traceID string, ok bool) {
	lineageMu.Lock()
	defer lineageMu.Unlock()
	p, found := lineageByService[serviceName]
	if !found || time.Since(p.timestamp) > maxAge {
		return "", "", false
	}
	return p.spanID, p.traceID, true
}

// maxParentAge bounds how stale a published parent span can be and still
// count as "the current chain reaching this service" - generous enough to
// tolerate the upstream plugin skipping a poll or two without falling back
// to an unlinked root, while still refusing a span from long ago.
const maxParentAge = 60 * time.Second

// SpanRequest is what every span-producing plugin hands to SubmitSpan
// instead of building a telemetryapi.Span and sending it directly.
type SpanRequest struct {
	ServiceName string
	Name        string
	Timestamp   time.Time
	Duration    time.Duration
	Attributes  map[string]interface{}

	// ID is this span's own ID. Leave empty to have SubmitSpan generate
	// one - only set it explicitly when another span submitted in the same
	// batch needs to reference it as a parent (see ParentID below).
	ID string

	// TraceID/ParentID: set both explicitly when this plugin already knows
	// the exact parent it wants (e.g. a caller/broker pair, or a
	// caller/proxy/upstream chain, all built within one function call).
	// SubmitSpan uses them as-is - no lookup. Leave both empty and set
	// ParentFrom instead to chain onto another service's most recently
	// submitted span. Leave everything empty for an intentionally unlinked
	// root.
	TraceID  string
	ParentID string

	// ParentFrom is the service name whose most recently submitted span
	// this one should chain onto, when this plugin has no locally-known
	// parent of its own (e.g. postgresspans.go's periodic self-report,
	// which has no caller in the same call). Ignored if TraceID/ParentID
	// are already set explicitly.
	ParentFrom string
}

// SubmitSpan resolves req's trace/parent linkage, sends it through the one
// shared harvester, and - on success - publishes it so a later SubmitSpan
// can chain onto it in turn. This is the only function in this package
// that calls harvester.RecordSpan.
func SubmitSpan(req SpanRequest) {
	span := telemetryapi.Span{
		ID:          req.ID,
		ServiceName: req.ServiceName,
		Name:        req.Name,
		Timestamp:   req.Timestamp,
		Duration:    req.Duration,
		Attributes:  req.Attributes,
	}
	if span.ID == "" {
		span.ID = randHex(8)
	}

	switch {
	case req.TraceID != "":
		span.TraceID = req.TraceID
		span.ParentID = req.ParentID
	case req.ParentFrom != "":
		if pSpanID, pTraceID, ok := lookupParent(req.ParentFrom, maxParentAge); ok {
			span.TraceID = pTraceID
			span.ParentID = pSpanID
		} else {
			tlLog.WithField("service", req.ServiceName).WithField("parent_from", req.ParentFrom).
				Debug("no recent span published for parent_from, sending unlinked root instead")
			span.TraceID = randHex(16)
		}
	default:
		span.TraceID = randHex(16)
	}

	if sharedHarvester == nil {
		tlLog.WithField("service", req.ServiceName).Warn("shared harvester not initialized, dropping span")
		return
	}
	if err := sharedHarvester.RecordSpan(span); err != nil {
		tlLog.WithError(err).WithField("service", req.ServiceName).Error("failed to record span")
		return
	}
	publishSpan(span)
}

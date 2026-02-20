package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type latencyAggregate struct {
	Count uint64
	Sum   float64
}

type gatewayMetrics struct {
	mu sync.Mutex

	authRejects      map[string]uint64
	replayDetections uint64
	inFlightRequests uint64

	upstreamRequests map[string]uint64
	upstreamLatency  map[string]latencyAggregate
	upstreamErrors   map[string]uint64

	mcpDiscovery       map[string]uint64
	mcpToolCalls       map[string]uint64
	shutdownDrainStats map[string]latencyAggregate
}

var gatewayMetricRegistry = newGatewayMetrics()

func newGatewayMetrics() *gatewayMetrics {
	return &gatewayMetrics{
		authRejects:        make(map[string]uint64, 16),
		upstreamRequests:   make(map[string]uint64, 16),
		upstreamLatency:    make(map[string]latencyAggregate, 16),
		upstreamErrors:     make(map[string]uint64, 16),
		mcpDiscovery:       make(map[string]uint64, 8),
		mcpToolCalls:       make(map[string]uint64, 8),
		shutdownDrainStats: make(map[string]latencyAggregate, 4),
	}
}

func (m *gatewayMetrics) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authRejects = map[string]uint64{}
	m.replayDetections = 0
	m.inFlightRequests = 0
	m.upstreamRequests = map[string]uint64{}
	m.upstreamLatency = map[string]latencyAggregate{}
	m.upstreamErrors = map[string]uint64{}
	m.mcpDiscovery = map[string]uint64{}
	m.mcpToolCalls = map[string]uint64{}
	m.shutdownDrainStats = map[string]latencyAggregate{}
}

func (m *gatewayMetrics) recordAuthReject(reasonCode string) {
	reason := normalizeMetricLabel(reasonCode, "unknown")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authRejects[reason]++
	if reason == normalizeMetricLabel(codeAuthReplayDetected, "unknown") {
		m.replayDetections++
	}
}

func (m *gatewayMetrics) observeUpstream(protocol string, outcome string, duration time.Duration) {
	proto := normalizeMetricLabel(protocol, "unknown")
	result := normalizeMetricLabel(outcome, "unknown")
	key := proto + "|" + result

	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamRequests[key]++
	agg := m.upstreamLatency[key]
	agg.Count++
	agg.Sum += duration.Seconds()
	m.upstreamLatency[key] = agg
}

func (m *gatewayMetrics) recordUpstreamError(class string) {
	errorClass := normalizeMetricLabel(class, "unknown")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamErrors[errorClass]++
}

func (m *gatewayMetrics) recordMCPDiscovery(result string) {
	normalized := normalizeMetricLabel(result, "unknown")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mcpDiscovery[normalized]++
}

func (m *gatewayMetrics) recordMCPToolCall(result string) {
	normalized := normalizeMetricLabel(result, "unknown")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mcpToolCalls[normalized]++
}

func (m *gatewayMetrics) recordRequestStart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlightRequests++
}

func (m *gatewayMetrics) recordRequestFinish() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inFlightRequests > 0 {
		m.inFlightRequests--
	}
}

func (m *gatewayMetrics) recordShutdownDrain(outcome string, duration time.Duration) {
	result := normalizeMetricLabel(outcome, "unknown")
	m.mu.Lock()
	defer m.mu.Unlock()
	agg := m.shutdownDrainStats[result]
	agg.Count++
	agg.Sum += duration.Seconds()
	m.shutdownDrainStats[result] = agg
}

func (m *gatewayMetrics) renderPrometheus() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var builder strings.Builder
	writeMetricHeader(&builder, "sigilum_gateway_auth_reject_total", "counter", "Total proxy auth rejects by reason code.")
	writeMetricHeader(&builder, "sigilum_gateway_replay_detected_total", "counter", "Total replay detections from signature nonce cache.")
	writeMetricHeader(&builder, "sigilum_gateway_requests_in_flight", "gauge", "Current number of in-flight HTTP requests.")
	writeMetricHeader(&builder, "sigilum_gateway_upstream_requests_total", "counter", "Total upstream requests by protocol/outcome.")
	writeMetricHeader(&builder, "sigilum_gateway_upstream_latency_seconds", "summary", "Observed upstream latency by protocol/outcome.")
	writeMetricHeader(&builder, "sigilum_gateway_upstream_error_total", "counter", "Total upstream failures by class.")
	writeMetricHeader(&builder, "sigilum_gateway_mcp_discovery_total", "counter", "Total MCP discovery attempts by result.")
	writeMetricHeader(&builder, "sigilum_gateway_mcp_tool_call_total", "counter", "Total MCP tool calls by result.")
	writeMetricHeader(&builder, "sigilum_gateway_shutdown_drain_total", "counter", "Total gateway graceful shutdown drain attempts by outcome.")
	writeMetricHeader(&builder, "sigilum_gateway_shutdown_drain_seconds", "summary", "Observed graceful shutdown drain durations by outcome.")

	for _, reason := range sortedMapKeys(m.authRejects) {
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_auth_reject_total{reason=%q} %d\n",
			escapePromLabel(reason),
			m.authRejects[reason],
		)
	}
	fmt.Fprintf(&builder, "sigilum_gateway_replay_detected_total %d\n", m.replayDetections)
	fmt.Fprintf(&builder, "sigilum_gateway_requests_in_flight %d\n", m.inFlightRequests)

	for _, key := range sortedMapKeys(m.upstreamRequests) {
		protocol, outcome := splitMetricKey(key)
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_upstream_requests_total{protocol=%q,outcome=%q} %d\n",
			escapePromLabel(protocol),
			escapePromLabel(outcome),
			m.upstreamRequests[key],
		)
	}
	for _, key := range sortedLatencyKeys(m.upstreamLatency) {
		protocol, outcome := splitMetricKey(key)
		agg := m.upstreamLatency[key]
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_upstream_latency_seconds_count{protocol=%q,outcome=%q} %d\n",
			escapePromLabel(protocol),
			escapePromLabel(outcome),
			agg.Count,
		)
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_upstream_latency_seconds_sum{protocol=%q,outcome=%q} %.6f\n",
			escapePromLabel(protocol),
			escapePromLabel(outcome),
			agg.Sum,
		)
	}

	for _, class := range sortedMapKeys(m.upstreamErrors) {
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_upstream_error_total{class=%q} %d\n",
			escapePromLabel(class),
			m.upstreamErrors[class],
		)
	}
	for _, result := range sortedMapKeys(m.mcpDiscovery) {
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_mcp_discovery_total{result=%q} %d\n",
			escapePromLabel(result),
			m.mcpDiscovery[result],
		)
	}
	for _, result := range sortedMapKeys(m.mcpToolCalls) {
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_mcp_tool_call_total{result=%q} %d\n",
			escapePromLabel(result),
			m.mcpToolCalls[result],
		)
	}
	for _, outcome := range sortedLatencyKeys(m.shutdownDrainStats) {
		agg := m.shutdownDrainStats[outcome]
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_shutdown_drain_total{outcome=%q} %d\n",
			escapePromLabel(outcome),
			agg.Count,
		)
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_shutdown_drain_seconds_count{outcome=%q} %d\n",
			escapePromLabel(outcome),
			agg.Count,
		)
		fmt.Fprintf(
			&builder,
			"sigilum_gateway_shutdown_drain_seconds_sum{outcome=%q} %.6f\n",
			escapePromLabel(outcome),
			agg.Sum,
		)
	}

	return builder.String()
}

func writeMetricHeader(builder *strings.Builder, name string, metricType string, help string) {
	fmt.Fprintf(builder, "# HELP %s %s\n", name, help)
	fmt.Fprintf(builder, "# TYPE %s %s\n", name, metricType)
}

func escapePromLabel(value string) string {
	replaced := strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(replaced, `"`, `\"`)
}

func normalizeMetricLabel(value string, fallback string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return fallback
	}
	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	out := strings.Trim(builder.String(), "_")
	out = strings.ReplaceAll(out, "__", "_")
	if out == "" {
		return fallback
	}
	return out
}

func sortedMapKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedLatencyKeys(values map[string]latencyAggregate) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func splitMetricKey(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return key, "unknown"
	}
	return parts[0], parts[1]
}

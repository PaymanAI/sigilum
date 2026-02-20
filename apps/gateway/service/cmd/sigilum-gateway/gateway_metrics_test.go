package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sigilum.local/gateway/config"
)

func TestGatewayMetricsRenderPrometheusIncludesCoreSeries(t *testing.T) {
	metrics := newGatewayMetrics()
	metrics.recordAuthReject(codeAuthHeadersInvalid)
	metrics.recordAuthReject(codeAuthReplayDetected)
	metrics.observeUpstream("http", "success", 150*time.Millisecond)
	metrics.observeUpstream("mcp", "error", 75*time.Millisecond)
	metrics.recordUpstreamError("UPSTREAM_ERROR")
	metrics.recordMCPDiscovery("success")
	metrics.recordMCPToolCall("forbidden")

	output := metrics.renderPrometheus()
	expectedSnippets := []string{
		`sigilum_gateway_auth_reject_total{reason="auth_headers_invalid"} 1`,
		`sigilum_gateway_auth_reject_total{reason="auth_replay_detected"} 1`,
		`sigilum_gateway_replay_detected_total 1`,
		`sigilum_gateway_upstream_requests_total{protocol="http",outcome="success"} 1`,
		`sigilum_gateway_upstream_requests_total{protocol="mcp",outcome="error"} 1`,
		`sigilum_gateway_upstream_error_total{class="upstream_error"} 1`,
		`sigilum_gateway_mcp_discovery_total{result="success"} 1`,
		`sigilum_gateway_mcp_tool_call_total{result="forbidden"} 1`,
	}
	for _, snippet := range expectedSnippets {
		if !strings.Contains(output, snippet) {
			t.Fatalf("expected metrics output to contain %q, got:\n%s", snippet, output)
		}
	}
}

func TestMetricsRouteRequiresAdminAccess(t *testing.T) {
	gatewayMetricRegistry.reset()
	t.Cleanup(gatewayMetricRegistry.reset)

	mux := http.NewServeMux()
	registerMetricsRoute(mux, config.Config{
		AllowedOrigins:           map[string]struct{}{"https://allowed.example": {}},
		RequireSignedAdminChecks: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.30:48123"
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for non-loopback metrics request, got %d", recorder.Code)
	}
}

func TestMetricsRouteReturnsPrometheusText(t *testing.T) {
	gatewayMetricRegistry.reset()
	t.Cleanup(gatewayMetricRegistry.reset)
	gatewayMetricRegistry.recordAuthReject(codeAuthNonceInvalid)

	mux := http.NewServeMux()
	registerMetricsRoute(mux, config.Config{
		AllowedOrigins:           map[string]struct{}{"https://allowed.example": {}},
		RequireSignedAdminChecks: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:53000"
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected text/plain content type, got %q", contentType)
	}
	if !strings.Contains(recorder.Body.String(), `sigilum_gateway_auth_reject_total{reason="auth_nonce_invalid"} 1`) {
		t.Fatalf("expected auth reject metric in body, got %s", recorder.Body.String())
	}
}

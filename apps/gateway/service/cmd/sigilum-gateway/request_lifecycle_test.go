package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithInFlightRequestTrackingTracksGauge(t *testing.T) {
	gatewayMetricRegistry.reset()
	t.Cleanup(gatewayMetricRegistry.reset)

	sawInFlightDuringHandler := false
	handler := withInFlightRequestTracking(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics := gatewayMetricRegistry.renderPrometheus()
		sawInFlightDuringHandler = strings.Contains(metrics, "sigilum_gateway_requests_in_flight 1")
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !sawInFlightDuringHandler {
		t.Fatal("expected in-flight gauge to be 1 during request handling")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", recorder.Code)
	}
	after := gatewayMetricRegistry.renderPrometheus()
	if !strings.Contains(after, "sigilum_gateway_requests_in_flight 0") {
		t.Fatalf("expected in-flight gauge to return to 0, got metrics:\n%s", after)
	}
}

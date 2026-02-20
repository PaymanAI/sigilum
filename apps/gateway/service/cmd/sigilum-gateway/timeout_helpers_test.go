package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWithRequestTimeoutSetsDeadline(t *testing.T) {
	wrapped := withRequestTimeout(2*time.Second, func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("expected request context deadline")
		}
		remaining := time.Until(deadline)
		if remaining < 1500*time.Millisecond || remaining > 2500*time.Millisecond {
			t.Fatalf("expected remaining timeout near 2s, got %s", remaining)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	wrapped(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", recorder.Code)
	}
}

func TestWithRequestTimeoutDisabledLeavesContextDeadlineUnset(t *testing.T) {
	wrapped := withRequestTimeout(0, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); ok {
			t.Fatal("expected request context without deadline when timeout is disabled")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	wrapped(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204, got %d", recorder.Code)
	}
}

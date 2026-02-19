package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sigilum.local/gateway/config"
	"sigilum.local/gateway/internal/catalog"
	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
)

type adminRouterFixture struct {
	mux         *http.ServeMux
	catalogPath string
}

func newAdminRouterFixture(t *testing.T) adminRouterFixture {
	t.Helper()

	connectorDataDir := filepath.Join(t.TempDir(), "gateway-data")
	connectorService, err := connectors.NewService(connectorDataDir, "test-master-key")
	if err != nil {
		t.Fatalf("create connector service: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := connectorService.Close(); closeErr != nil {
			t.Fatalf("close connector service: %v", closeErr)
		}
	})

	catalogPath := filepath.Join(t.TempDir(), "service-catalog.json")
	catalogStore := catalog.NewStore(catalogPath)
	if _, err := catalogStore.Load(); err != nil {
		t.Fatalf("load catalog store: %v", err)
	}

	cfg := config.Config{
		AllowedOrigins:           map[string]struct{}{"https://allowed.example": {}},
		RequireSignedAdminChecks: true,
		MaxRequestBodyBytes:      2 << 20,
		SigilumHomeDir:           t.TempDir(),
	}

	mux := http.NewServeMux()
	registerAdminRoutes(mux, cfg, connectorService, catalogStore, mcpruntime.NewClient(2*time.Second))
	return adminRouterFixture{
		mux:         mux,
		catalogPath: catalogPath,
	}
}

func TestAdminRoutesRejectNonLoopbackRequests(t *testing.T) {
	fixture := newAdminRouterFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.RemoteAddr = "203.0.113.20:48123"
	recorder := httptest.NewRecorder()

	fixture.mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for non-loopback admin request, got %d", recorder.Code)
	}
	var payload errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON body, got decode error: %v", err)
	}
	if payload.Code != "ADMIN_ACCESS_FORBIDDEN" {
		t.Fatalf("expected ADMIN_ACCESS_FORBIDDEN code, got %q", payload.Code)
	}
}

func TestAdminRoutesAllowLoopbackAndPersistCatalogUpdates(t *testing.T) {
	fixture := newAdminRouterFixture(t)
	updatePayload := catalog.ServiceCatalog{
		Version:  "v1",
		Services: []catalog.ServiceTemplate{},
	}
	updateBody, err := json.Marshal(updatePayload)
	if err != nil {
		t.Fatalf("marshal catalog payload: %v", err)
	}

	putReq := httptest.NewRequest(http.MethodPut, "/api/admin/service-catalog", bytes.NewReader(updateBody))
	putReq.RemoteAddr = "127.0.0.1:53000"
	putRecorder := httptest.NewRecorder()
	fixture.mux.ServeHTTP(putRecorder, putReq)

	if putRecorder.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from catalog PUT, got %d body=%s", putRecorder.Code, putRecorder.Body.String())
	}
	if _, err := os.Stat(fixture.catalogPath); err != nil {
		t.Fatalf("expected catalog file to exist at %s: %v", fixture.catalogPath, err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/admin/service-catalog", nil)
	getReq.RemoteAddr = "127.0.0.1:53001"
	getRecorder := httptest.NewRecorder()
	fixture.mux.ServeHTTP(getRecorder, getReq)

	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from catalog GET, got %d", getRecorder.Code)
	}

	var loaded catalog.ServiceCatalog
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &loaded); err != nil {
		t.Fatalf("decode catalog GET response: %v", err)
	}
	if loaded.Version != "v1" {
		t.Fatalf("expected catalog version v1, got %q", loaded.Version)
	}
	if len(loaded.Services) != 0 {
		t.Fatalf("expected empty services list after update, got %d entries", len(loaded.Services))
	}
}

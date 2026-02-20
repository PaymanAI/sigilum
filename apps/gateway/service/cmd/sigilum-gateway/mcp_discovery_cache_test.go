package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

type stubMCPDiscoveryClient struct {
	calls    int
	discover func(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error)
}

func (s *stubMCPDiscoveryClient) Discover(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
	s.calls++
	if s.discover == nil {
		return connectors.MCPDiscovery{}, errors.New("discover function is not configured")
	}
	return s.discover(ctx, cfg)
}

func TestParseMCPDiscoveryRefreshMode(t *testing.T) {
	mode, err := parseMCPDiscoveryRefreshMode("", mcpDiscoveryRefreshModeAuto)
	if err != nil {
		t.Fatalf("parse default mode: %v", err)
	}
	if mode != mcpDiscoveryRefreshModeAuto {
		t.Fatalf("expected auto mode, got %q", mode)
	}

	mode, err = parseMCPDiscoveryRefreshMode("force", mcpDiscoveryRefreshModeAuto)
	if err != nil {
		t.Fatalf("parse force mode: %v", err)
	}
	if mode != mcpDiscoveryRefreshModeForce {
		t.Fatalf("expected force mode, got %q", mode)
	}

	if _, err := parseMCPDiscoveryRefreshMode("invalid", mcpDiscoveryRefreshModeAuto); err == nil {
		t.Fatal("expected invalid mode to fail")
	}
}

func TestIsMCPDiscoveryFresh(t *testing.T) {
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)
	discovery := connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "linear.searchIssues"}},
		LastDiscoveredAt: now.Add(-4 * time.Minute),
	}
	if !isMCPDiscoveryFresh(discovery, 5*time.Minute, now) {
		t.Fatal("expected discovery cache to be fresh")
	}
	if isMCPDiscoveryFresh(discovery, 3*time.Minute, now) {
		t.Fatal("expected discovery cache to be stale")
	}
}

func TestCanUseMCPDiscoveryStaleIfError(t *testing.T) {
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)
	discovery := connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "linear.searchIssues"}},
		LastDiscoveredAt: now.Add(-8 * time.Minute),
	}
	if !canUseMCPDiscoveryStaleIfError(discovery, 5*time.Minute, 10*time.Minute, now) {
		t.Fatal("expected stale-if-error window to allow fallback")
	}
	if canUseMCPDiscoveryStaleIfError(discovery, 5*time.Minute, 2*time.Minute, now) {
		t.Fatal("expected stale-if-error window to reject fallback")
	}
}

func TestResolveMCPDiscoveryUsesCacheHitWithoutRefresh(t *testing.T) {
	service := newTestMCPConnectorService(t)
	connectionID := seedTestMCPConnection(t, service)
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	_, err := service.SaveMCPDiscovery(connectionID, connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "linear.searchIssues"}},
		LastDiscoveredAt: now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save discovery: %v", err)
	}

	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		t.Fatalf("resolve proxy config: %v", err)
	}
	stubClient := &stubMCPDiscoveryClient{
		discover: func(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
			return connectors.MCPDiscovery{}, errors.New("unexpected discover call")
		},
	}

	resolution, err := resolveMCPDiscovery(
		context.Background(),
		connectionID,
		proxyCfg,
		service,
		stubClient,
		5*time.Minute,
		30*time.Minute,
		mcpDiscoveryRefreshModeAuto,
		now,
	)
	if err != nil {
		t.Fatalf("resolve discovery: %v", err)
	}
	if resolution.Source != mcpDiscoverySourceCacheHit {
		t.Fatalf("expected cache hit source, got %q", resolution.Source)
	}
	if resolution.AttemptedRefresh {
		t.Fatal("expected cache hit without refresh attempt")
	}
	if stubClient.calls != 0 {
		t.Fatalf("expected no discovery calls, got %d", stubClient.calls)
	}
}

func TestResolveMCPDiscoveryRefreshesWhenStale(t *testing.T) {
	service := newTestMCPConnectorService(t)
	connectionID := seedTestMCPConnection(t, service)
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	_, err := service.SaveMCPDiscovery(connectionID, connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "old.tool"}},
		LastDiscoveredAt: now.Add(-20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save discovery: %v", err)
	}

	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		t.Fatalf("resolve proxy config: %v", err)
	}
	stubClient := &stubMCPDiscoveryClient{
		discover: func(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
			return connectors.MCPDiscovery{
				Tools: []connectors.MCPTool{{Name: "new.tool"}},
			}, nil
		},
	}

	resolution, err := resolveMCPDiscovery(
		context.Background(),
		connectionID,
		proxyCfg,
		service,
		stubClient,
		5*time.Minute,
		30*time.Minute,
		mcpDiscoveryRefreshModeAuto,
		now,
	)
	if err != nil {
		t.Fatalf("resolve discovery: %v", err)
	}
	if resolution.Source != mcpDiscoverySourceRefreshed {
		t.Fatalf("expected refreshed source, got %q", resolution.Source)
	}
	if !resolution.AttemptedRefresh {
		t.Fatal("expected refresh attempt")
	}
	if len(resolution.Connection.MCPDiscovery.Tools) != 1 || resolution.Connection.MCPDiscovery.Tools[0].Name != "new.tool" {
		t.Fatalf("expected refreshed tool list, got %#v", resolution.Connection.MCPDiscovery.Tools)
	}
	if stubClient.calls != 1 {
		t.Fatalf("expected one discovery call, got %d", stubClient.calls)
	}
}

func TestResolveMCPDiscoveryFallsBackToStaleOnError(t *testing.T) {
	service := newTestMCPConnectorService(t)
	connectionID := seedTestMCPConnection(t, service)
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	_, err := service.SaveMCPDiscovery(connectionID, connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "stale.tool"}},
		LastDiscoveredAt: now.Add(-6 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save discovery: %v", err)
	}

	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		t.Fatalf("resolve proxy config: %v", err)
	}
	stubClient := &stubMCPDiscoveryClient{
		discover: func(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
			return connectors.MCPDiscovery{}, errors.New("upstream unavailable")
		},
	}

	resolution, err := resolveMCPDiscovery(
		context.Background(),
		connectionID,
		proxyCfg,
		service,
		stubClient,
		5*time.Minute,
		10*time.Minute,
		mcpDiscoveryRefreshModeAuto,
		now,
	)
	if err != nil {
		t.Fatalf("resolve discovery: %v", err)
	}
	if resolution.Source != mcpDiscoverySourceStaleIfError {
		t.Fatalf("expected stale-if-error source, got %q", resolution.Source)
	}
	if resolution.RefreshError == nil {
		t.Fatal("expected refresh error to be retained for stale fallback")
	}
	if len(resolution.Connection.MCPDiscovery.Tools) != 1 || resolution.Connection.MCPDiscovery.Tools[0].Name != "stale.tool" {
		t.Fatalf("expected stale tool list, got %#v", resolution.Connection.MCPDiscovery.Tools)
	}
	if resolution.Connection.MCPDiscovery.LastDiscoveryError == "" {
		t.Fatal("expected discovery error to be persisted")
	}
}

func TestResolveMCPDiscoveryForceRefreshFailsOnError(t *testing.T) {
	service := newTestMCPConnectorService(t)
	connectionID := seedTestMCPConnection(t, service)
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	_, err := service.SaveMCPDiscovery(connectionID, connectors.MCPDiscovery{
		Tools:            []connectors.MCPTool{{Name: "stale.tool"}},
		LastDiscoveredAt: now.Add(-6 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save discovery: %v", err)
	}

	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		t.Fatalf("resolve proxy config: %v", err)
	}
	stubClient := &stubMCPDiscoveryClient{
		discover: func(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
			return connectors.MCPDiscovery{}, errors.New("upstream unavailable")
		},
	}

	if _, err := resolveMCPDiscovery(
		context.Background(),
		connectionID,
		proxyCfg,
		service,
		stubClient,
		5*time.Minute,
		10*time.Minute,
		mcpDiscoveryRefreshModeForce,
		now,
	); err == nil {
		t.Fatal("expected force refresh to fail when discovery fails")
	}
}

func newTestMCPConnectorService(t *testing.T) *connectors.Service {
	t.Helper()
	service, err := connectors.NewService(t.TempDir(), "test-master-key")
	if err != nil {
		t.Fatalf("create connector service: %v", err)
	}
	t.Cleanup(func() {
		_ = service.Close()
	})
	return service
}

func seedTestMCPConnection(t *testing.T, service *connectors.Service) string {
	t.Helper()
	connectionID := "linear-mcp"
	_, err := service.CreateConnection(connectors.CreateConnectionInput{
		ID:           connectionID,
		Name:         "Linear MCP",
		Protocol:     "mcp",
		BaseURL:      "https://mcp.linear.example",
		AuthMode:     "header_key",
		MCPTransport: "streamable_http",
		MCPEndpoint:  "/mcp",
	})
	if err != nil {
		t.Fatalf("create mcp connection: %v", err)
	}
	return connectionID
}

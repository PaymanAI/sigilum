package connectors

import (
	"testing"
)

func TestCreateConnectionMCPWithoutSecrets(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	conn, err := service.CreateConnection(CreateConnectionInput{
		ID:       "linear-mcp",
		Name:     "Linear MCP",
		Protocol: "mcp",
		BaseURL:  "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("expected mcp create success, got error: %v", err)
	}
	if conn.Protocol != ConnectionProtocolMCP {
		t.Fatalf("expected protocol mcp, got %s", conn.Protocol)
	}
	if conn.MCPTransport != MCPTransportStreamableHTTP {
		t.Fatalf("expected default mcp transport, got %s", conn.MCPTransport)
	}
}

func TestCreateConnectionHTTPRequiresAuthSecretKey(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	_, err := service.CreateConnection(CreateConnectionInput{
		ID:       "stripe-http",
		Name:     "Stripe",
		Protocol: "http",
		BaseURL:  "https://api.stripe.com",
		Secrets:  map[string]string{"api_key": "sk_test"},
	})
	if err == nil {
		t.Fatal("expected auth_secret_key validation error")
	}
}

func TestResolveProxyConfigAllowsMCPWithoutAuthSecret(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	_, err := service.CreateConnection(CreateConnectionInput{
		ID:       "mcp-no-auth",
		Name:     "MCP No Auth",
		Protocol: "mcp",
		BaseURL:  "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("create mcp connection failed: %v", err)
	}

	cfg, err := service.ResolveProxyConfig("mcp-no-auth")
	if err != nil {
		t.Fatalf("resolve proxy config failed: %v", err)
	}
	if cfg.Secret != "" {
		t.Fatalf("expected empty secret, got %q", cfg.Secret)
	}
}

func TestSaveMCPDiscovery(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	_, err := service.CreateConnection(CreateConnectionInput{
		ID:       "mcp-discovery",
		Name:     "MCP Discovery",
		Protocol: "mcp",
		BaseURL:  "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("create mcp connection failed: %v", err)
	}

	updated, err := service.SaveMCPDiscovery("mcp-discovery", MCPDiscovery{
		Server: MCPServerInfo{
			Name:            "linear",
			Version:         "1.0.0",
			ProtocolVersion: "2024-11-05",
		},
		Tools: []MCPTool{
			{Name: "linear.searchIssues"},
			{Name: "linear.searchIssues"},
			{Name: "linear.createComment"},
		},
	})
	if err != nil {
		t.Fatalf("save discovery failed: %v", err)
	}

	if len(updated.MCPDiscovery.Tools) != 2 {
		t.Fatalf("expected deduped tools, got %d", len(updated.MCPDiscovery.Tools))
	}
	if updated.MCPDiscovery.LastDiscoveredAt == "" {
		t.Fatal("expected discovery timestamp")
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	service, err := NewService(t.TempDir(), "test-master-key")
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

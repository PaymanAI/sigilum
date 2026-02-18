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

func TestResolveProxyConfigInjectsSharedCredentialVariable(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	_, err := service.UpsertCredentialVariable(UpsertSharedCredentialVariableInput{
		Key:   "OPENAI_API_KEY",
		Value: "sk-live-123",
	})
	if err != nil {
		t.Fatalf("upsert credential variable failed: %v", err)
	}

	_, err = service.CreateConnection(CreateConnectionInput{
		ID:            "openai-http",
		Name:          "OpenAI",
		Protocol:      "http",
		BaseURL:       "https://api.openai.com",
		AuthMode:      "bearer",
		AuthSecretKey: "api_key",
		Secrets: map[string]string{
			"api_key": "{{var:OPENAI_API_KEY}}",
		},
	})
	if err != nil {
		t.Fatalf("create connection failed: %v", err)
	}

	cfg, err := service.ResolveProxyConfig("openai-http")
	if err != nil {
		t.Fatalf("resolve proxy config failed: %v", err)
	}
	if cfg.Secret != "sk-live-123" {
		t.Fatalf("expected injected secret, got %q", cfg.Secret)
	}
}

func TestResolveProxyConfigFailsWhenSharedCredentialVariableMissing(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	_, err := service.CreateConnection(CreateConnectionInput{
		ID:            "linear-http",
		Name:          "Linear",
		Protocol:      "http",
		BaseURL:       "https://api.linear.app",
		AuthMode:      "header_key",
		AuthSecretKey: "api_key",
		Secrets: map[string]string{
			"api_key": "{{var:LINEAR_API_KEY}}",
		},
	})
	if err != nil {
		t.Fatalf("create connection failed: %v", err)
	}

	_, err = service.ResolveProxyConfig("linear-http")
	if err == nil {
		t.Fatal("expected missing credential variable error")
	}
}

func TestCredentialVariableLifecycle(t *testing.T) {
	service := newTestService(t)
	defer service.Close()

	created, err := service.UpsertCredentialVariable(UpsertSharedCredentialVariableInput{
		Key:              "STRIPE_API_KEY",
		Value:            "sk_test_123",
		CreatedBySubject: "user_123",
	})
	if err != nil {
		t.Fatalf("upsert variable failed: %v", err)
	}
	if created.Key != "STRIPE_API_KEY" {
		t.Fatalf("unexpected key: %s", created.Key)
	}
	if created.CreatedBySubject != "user_123" {
		t.Fatalf("unexpected created_by_subject: %s", created.CreatedBySubject)
	}

	updated, err := service.UpsertCredentialVariable(UpsertSharedCredentialVariableInput{
		Key:              "STRIPE_API_KEY",
		Value:            "sk_test_456",
		CreatedBySubject: "user_999",
	})
	if err != nil {
		t.Fatalf("second upsert variable failed: %v", err)
	}
	if updated.CreatedBySubject != "user_123" {
		t.Fatalf("created_by_subject should remain initial creator, got %s", updated.CreatedBySubject)
	}

	list, err := service.ListCredentialVariables()
	if err != nil {
		t.Fatalf("list variables failed: %v", err)
	}
	if len(list) != 1 || list[0].Key != "STRIPE_API_KEY" {
		t.Fatalf("unexpected list result: %#v", list)
	}
	if list[0].CreatedBySubject != "user_123" {
		t.Fatalf("list missing created_by_subject: %#v", list[0])
	}

	if err := service.DeleteCredentialVariable("STRIPE_API_KEY"); err != nil {
		t.Fatalf("delete variable failed: %v", err)
	}
	if err := service.DeleteCredentialVariable("STRIPE_API_KEY"); err == nil {
		t.Fatal("expected not found after delete")
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

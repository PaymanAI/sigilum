package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sigilum.local/gateway/config"
	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
)

func TestHandleMCPRequestRateLimitsToolCalls(t *testing.T) {
	configureGatewayRateLimiters(config.Config{
		ClaimRegistrationRateLimit: 0,
		MCPToolCallRateLimit:       1,
	})
	t.Cleanup(func() {
		configureGatewayRateLimiters(config.Config{
			ClaimRegistrationRateLimit: 0,
			MCPToolCallRateLimit:       0,
		})
	})

	var (
		mu             sync.Mutex
		toolCallCount  int
		initializeSeen int
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			mu.Lock()
			initializeSeen++
			mu.Unlock()
			w.Header().Set("Mcp-Session-Id", "fixture-session")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]any{
						"name":    "fixture-mcp",
						"version": "1.0.0",
					},
				},
			})
		case "tools/call":
			mu.Lock()
			toolCallCount++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "ok"},
					},
				},
			})
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	defer upstream.Close()

	connectorService, err := connectors.NewService(t.TempDir(), "test-master-key")
	if err != nil {
		t.Fatalf("create connector service: %v", err)
	}
	t.Cleanup(func() {
		_ = connectorService.Close()
	})

	if _, err := connectorService.CreateConnection(connectors.CreateConnectionInput{
		ID:       "demo",
		Name:     "demo",
		Protocol: "mcp",
		BaseURL:  upstream.URL,
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := connectorService.SaveMCPDiscovery("demo", connectors.MCPDiscovery{
		Tools: []connectors.MCPTool{
			{Name: "demo.echo", Description: "echo"},
		},
		LastDiscoveredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save discovery: %v", err)
	}

	cfg := config.Config{
		LogProxyRequests:         false,
		AllowUnsignedProxy:       true,
		AllowUnsignedFor:         map[string]struct{}{"demo": {}},
		MaxRequestBodyBytes:      2 << 20,
		MCPDiscoveryCacheTTL:     5 * time.Minute,
		MCPDiscoveryStaleIfError: time.Hour,
		RotationEnforcement:      "off",
	}

	nonceCache := newNonceReplayCache(time.Minute, "")
	mcpClient := mcpruntime.NewClient(2 * time.Second)

	firstReq := httptest.NewRequest(http.MethodPost, "/mcp/demo/tools/demo.echo/call", strings.NewReader(`{"arguments":{"q":"hello"}}`))
	firstReq.Header.Set("Content-Type", "application/json")
	firstRes := httptest.NewRecorder()
	handleMCPRequest(firstRes, firstReq, nonceCache, nil, connectorService, mcpClient, cfg)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("expected first mcp call to pass, got %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/mcp/demo/tools/demo.echo/call", strings.NewReader(`{"arguments":{"q":"hello"}}`))
	secondReq.Header.Set("Content-Type", "application/json")
	secondRes := httptest.NewRecorder()
	handleMCPRequest(secondRes, secondReq, nonceCache, nil, connectorService, mcpClient, cfg)
	if secondRes.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second mcp call to be rate-limited, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
	var payload errorResponse
	if err := json.Unmarshal(secondRes.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode rate-limit response: %v", err)
	}
	if payload.Code != codeMCPToolRateLimited {
		t.Fatalf("expected %s, got %s", codeMCPToolRateLimited, payload.Code)
	}

	mu.Lock()
	finalToolCallCount := toolCallCount
	finalInitializeSeen := initializeSeen
	mu.Unlock()
	if finalInitializeSeen == 0 {
		t.Fatal("expected upstream initialize request during first call")
	}
	if finalToolCallCount != 1 {
		t.Fatalf("expected exactly one upstream tools/call request after rate-limiting, got %d", finalToolCallCount)
	}
}

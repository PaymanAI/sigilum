package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

func TestResolveEndpoint(t *testing.T) {
	conn := connectors.Connection{
		Protocol:    connectors.ConnectionProtocolMCP,
		BaseURL:     "https://api.example.com/v1",
		MCPEndpoint: "/mcp",
	}

	endpoint, err := resolveEndpoint(conn)
	if err != nil {
		t.Fatalf("resolve endpoint failed: %v", err)
	}
	if endpoint != "https://api.example.com/v1/mcp" {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
}

func TestDiscoverAndCallTool(t *testing.T) {
	var mu sync.Mutex
	handlerErr := ""
	setHandlerErr := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		if handlerErr == "" {
			handlerErr = message
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			setHandlerErr("expected authorization header, got " + got)
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			setHandlerErr("decode request failed")
			http.Error(w, "decode request failed", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]any{
						"name":    "test-mcp",
						"version": "1.0.0",
					},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "linear.searchIssues",
							"description": "Search issues",
							"inputSchema": map[string]any{"type": "object"},
						},
					},
				},
			})
		case "tools/call":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "ok"},
					},
				},
			})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := NewClient(5 * time.Second)
	cfg := connectors.ProxyConfig{
		Connection: connectors.Connection{
			Protocol:   connectors.ConnectionProtocolMCP,
			BaseURL:    server.URL,
			AuthMode:   connectors.AuthModeBearer,
			AuthPrefix: "Bearer ",
		},
		Secret: "token-123",
	}

	discovery, err := client.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if discovery.Server.Name != "test-mcp" {
		t.Fatalf("unexpected server name: %s", discovery.Server.Name)
	}
	if len(discovery.Tools) != 1 || discovery.Tools[0].Name != "linear.searchIssues" {
		t.Fatalf("unexpected tools: %#v", discovery.Tools)
	}

	result, err := client.CallTool(context.Background(), cfg, "linear.searchIssues", json.RawMessage(`{"q":"auth"}`))
	if err != nil {
		t.Fatalf("call tool failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty call result")
	}
	if handlerErr != "" {
		t.Fatalf("server handler assertion failed: %s", handlerErr)
	}
}

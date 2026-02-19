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

func TestResolveEndpointPreservesRelativeQueryParams(t *testing.T) {
	conn := connectors.Connection{
		Protocol:    connectors.ConnectionProtocolMCP,
		BaseURL:     "https://mcp.typefully.com",
		MCPEndpoint: "/mcp?TYPEFULLY_API_KEY={{__API_KEY__}}",
	}

	endpoint, err := resolveEndpoint(conn)
	if err != nil {
		t.Fatalf("resolve endpoint failed: %v", err)
	}
	if endpoint != "https://mcp.typefully.com/mcp?TYPEFULLY_API_KEY=%7B%7B__API_KEY__%7D%7D" {
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

func TestDiscoverWithQueryParamAuth(t *testing.T) {
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
		if got := r.URL.Query().Get("TYPEFULLY_API_KEY"); got != "tfy-123" {
			setHandlerErr("expected TYPEFULLY_API_KEY query param")
			http.Error(w, "missing query auth", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Authorization"); got != "" {
			setHandlerErr("unexpected authorization header in query_param mode")
			http.Error(w, "unexpected authorization header", http.StatusBadRequest)
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
						"name":    "typefully-mcp",
						"version": "1.0.0",
					},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"tools": []map[string]any{},
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
			Protocol:       connectors.ConnectionProtocolMCP,
			BaseURL:        server.URL,
			AuthMode:       connectors.AuthModeQueryParam,
			AuthHeaderName: "TYPEFULLY_API_KEY",
		},
		Secret: "tfy-123",
	}

	if _, err := client.Discover(context.Background(), cfg); err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if handlerErr != "" {
		t.Fatalf("server handler assertion failed: %s", handlerErr)
	}
}

func TestDiscoverInitializeOmitsSessionHeader(t *testing.T) {
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
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			setHandlerErr("decode request failed")
			http.Error(w, "decode request failed", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			if got := r.Header.Get("Mcp-Session-Id"); got != "" {
				setHandlerErr("initialize must not send session header")
				http.Error(w, "invalid initialize", http.StatusBadRequest)
				return
			}
			w.Header().Set("Mcp-Session-Id", "fresh-session")
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
			if got := r.Header.Get("Mcp-Session-Id"); got != "fresh-session" {
				setHandlerErr("tools/list expected fresh session header")
				http.Error(w, "missing session", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"tools": []map[string]any{},
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
			Protocol: connectors.ConnectionProtocolMCP,
			BaseURL:  server.URL,
		},
	}

	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		t.Fatalf("resolve endpoint failed: %v", err)
	}
	client.setSessionID(endpoint, "stale-session")

	_, err = client.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if handlerErr != "" {
		t.Fatalf("server handler assertion failed: %s", handlerErr)
	}
}

func TestCallToolBootstrapsSessionWhenMissing(t *testing.T) {
	var (
		mu                 sync.Mutex
		handlerErr         string
		lastIssuedSession  string
		initializeRequests int
		callRequests       int
	)
	setHandlerErr := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		if handlerErr == "" {
			handlerErr = message
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			setHandlerErr("decode request failed")
			http.Error(w, "decode request failed", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			initializeRequests++
			lastIssuedSession = "session-bootstrapped"
			w.Header().Set("Mcp-Session-Id", lastIssuedSession)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]any{
						"name":    "linear-mcp",
						"version": "1.0.0",
					},
				},
			})
		case "tools/call":
			callRequests++
			if got := r.Header.Get("Mcp-Session-Id"); got == "" {
				http.Error(w, "Mcp-Session-Id required", http.StatusBadRequest)
				return
			} else if got != lastIssuedSession {
				http.Error(w, "unknown session", http.StatusBadRequest)
				return
			}
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
			Protocol: connectors.ConnectionProtocolMCP,
			BaseURL:  server.URL,
		},
	}

	result, err := client.CallTool(context.Background(), cfg, "list_issues", json.RawMessage(`{"limit":1}`))
	if err != nil {
		t.Fatalf("call tool failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty call result")
	}
	if initializeRequests == 0 {
		t.Fatal("expected initialize request before tool call")
	}
	if callRequests != 1 {
		t.Fatalf("expected one tools/call request, got %d", callRequests)
	}
	if handlerErr != "" {
		t.Fatalf("server handler assertion failed: %s", handlerErr)
	}
}

func TestCallToolReinitializesOnSessionError(t *testing.T) {
	var (
		mu                 sync.Mutex
		handlerErr         string
		lastIssuedSession  string
		initializeRequests int
		callRequests       int
	)
	setHandlerErr := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		if handlerErr == "" {
			handlerErr = message
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			setHandlerErr("decode request failed")
			http.Error(w, "decode request failed", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			initializeRequests++
			lastIssuedSession = "fresh-session"
			w.Header().Set("Mcp-Session-Id", lastIssuedSession)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "sigilum-gateway",
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]any{
						"name":    "linear-mcp",
						"version": "1.0.0",
					},
				},
			})
		case "tools/call":
			callRequests++
			got := r.Header.Get("Mcp-Session-Id")
			if got == "" {
				http.Error(w, "Mcp-Session-Id required", http.StatusBadRequest)
				return
			}
			if got != lastIssuedSession {
				http.Error(w, "invalid session id", http.StatusBadRequest)
				return
			}
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
			Protocol: connectors.ConnectionProtocolMCP,
			BaseURL:  server.URL,
		},
	}

	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		t.Fatalf("resolve endpoint failed: %v", err)
	}
	client.setSessionID(endpoint, "stale-session")

	result, err := client.CallTool(context.Background(), cfg, "list_issues", json.RawMessage(`{"limit":1}`))
	if err != nil {
		t.Fatalf("call tool failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty call result")
	}
	if initializeRequests == 0 {
		t.Fatal("expected initialize request after session error")
	}
	if callRequests < 2 {
		t.Fatalf("expected at least two tools/call attempts (stale + retry), got %d", callRequests)
	}
	if handlerErr != "" {
		t.Fatalf("server handler assertion failed: %s", handlerErr)
	}
}

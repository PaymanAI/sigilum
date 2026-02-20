package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigilum.local/gateway/config"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/gateway/internal/connectors"
)

func TestValidateSignatureComponentsNoBody(t *testing.T) {
	input := `sig1=("@method" "@target-uri" "sigilum-namespace" "sigilum-subject" "sigilum-agent-key" "sigilum-agent-cert");created=1;keyid="did:sigilum:alice#ed25519-test";alg="ed25519";nonce="abc"`
	if err := validateSignatureComponents(input, false); err != nil {
		t.Fatalf("expected valid component set, got error: %v", err)
	}
}

func TestValidateSignatureComponentsWithBody(t *testing.T) {
	input := `sig1=("@method" "@target-uri" "content-digest" "sigilum-namespace" "sigilum-subject" "sigilum-agent-key" "sigilum-agent-cert");created=1;keyid="did:sigilum:alice#ed25519-test";alg="ed25519";nonce="abc"`
	if err := validateSignatureComponents(input, true); err != nil {
		t.Fatalf("expected valid component set, got error: %v", err)
	}
}

func TestValidateSignatureComponentsRejectsWrongSet(t *testing.T) {
	input := `sig1=("@method" "@target-uri" "sigilum-namespace" "sigilum-agent-key");created=1;keyid="did:sigilum:alice#ed25519-test";alg="ed25519";nonce="abc"`
	err := validateSignatureComponents(input, false)
	if !errors.Is(err, errInvalidSignedComponentSet) {
		t.Fatalf("expected invalid component set error, got: %v", err)
	}
}

func TestValidateSignatureComponentsRejectsMalformedInput(t *testing.T) {
	err := validateSignatureComponents("not-a-signature-input", false)
	if !errors.Is(err, errInvalidSignatureInputFormat) {
		t.Fatalf("expected invalid Signature-Input format error, got: %v", err)
	}
}

func TestRequestAbsoluteURLIgnoresForwardedProtoFromUntrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/proxy/slack", nil)
	req.Host = "gateway.example"
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("X-Forwarded-Proto", "https")

	if got := requestAbsoluteURL(req, nil); got != "http://gateway.example/proxy/slack" {
		t.Fatalf("expected untrusted forwarded proto to be ignored, got %q", got)
	}
}

func TestRequestAbsoluteURLUsesForwardedProtoFromTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/proxy/slack", nil)
	req.Host = "gateway.example"
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("X-Forwarded-Proto", "https")
	_, trustedCIDR, _ := net.ParseCIDR("203.0.113.0/24")

	if got := requestAbsoluteURL(req, []*net.IPNet{trustedCIDR}); got != "https://gateway.example/proxy/slack" {
		t.Fatalf("expected trusted forwarded proto to be used, got %q", got)
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/proxy/slack", nil)
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("X-Forwarded-For", "10.0.0.5")

	if got := clientIP(req, nil); got != "203.0.113.10" {
		t.Fatalf("expected remote addr IP for untrusted proxy, got %q", got)
	}
}

func TestClientIPUsesForwardedHeadersFromTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.local/proxy/slack", nil)
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.6")
	_, trustedCIDR, _ := net.ParseCIDR("203.0.113.0/24")

	if got := clientIP(req, []*net.IPNet{trustedCIDR}); got != "10.0.0.5" {
		t.Fatalf("expected first forwarded IP for trusted proxy, got %q", got)
	}
}

func TestIsLoopbackClient(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "ipv4 loopback", value: "127.0.0.1", expected: true},
		{name: "ipv6 loopback", value: "::1", expected: true},
		{name: "localhost hostname", value: "localhost", expected: true},
		{name: "public ip", value: "203.0.113.10", expected: false},
		{name: "empty", value: "", expected: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopbackClient(tc.value); got != tc.expected {
				t.Fatalf("expected %t for %q, got %t", tc.expected, tc.value, got)
			}
		})
	}
}

func TestEnforceAdminRequestAccessAllowsLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.RemoteAddr = "127.0.0.1:2345"
	recorder := httptest.NewRecorder()

	ok := enforceAdminRequestAccess(recorder, req, config.Config{
		RequireSignedAdminChecks: true,
		LogProxyRequests:         false,
	})
	if !ok {
		t.Fatal("expected loopback admin request to be allowed")
	}
}

func TestEnforceAdminRequestAccessRejectsNonLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.RemoteAddr = "203.0.113.10:2345"
	recorder := httptest.NewRecorder()

	ok := enforceAdminRequestAccess(recorder, req, config.Config{
		RequireSignedAdminChecks: true,
		LogProxyRequests:         false,
	})
	if ok {
		t.Fatal("expected non-loopback admin request to be rejected")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d", recorder.Code)
	}
	var payload errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON response, got error: %v", err)
	}
	if payload.Code != "ADMIN_ACCESS_FORBIDDEN" {
		t.Fatalf("expected ADMIN_ACCESS_FORBIDDEN, got %q", payload.Code)
	}
}

func TestEnforceAdminRequestAccessAllowsAdminTokenBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()

	ok := enforceAdminRequestAccess(recorder, req, config.Config{
		RequireSignedAdminChecks: true,
		AdminToken:               "test-admin-token",
		LogProxyRequests:         false,
	})
	if !ok {
		t.Fatal("expected token-authenticated admin request to be allowed")
	}
}

func TestEnforceAdminRequestAccessAllowsAdminTokenHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.RemoteAddr = "203.0.113.10:2345"
	req.Header.Set("X-Sigilum-Admin-Token", "test-admin-token")
	recorder := httptest.NewRecorder()

	ok := enforceAdminRequestAccess(recorder, req, config.Config{
		RequireSignedAdminChecks: true,
		AdminToken:               "test-admin-token",
		LogProxyRequests:         false,
	})
	if !ok {
		t.Fatal("expected header-authenticated admin request to be allowed")
	}
}

func TestResolveServiceAPIKeyPrefersScopedEnv(t *testing.T) {
	t.Setenv("SIGILUM_SERVICE_API_KEY_DEMO_SERVICE_GATEWAY", "scoped-key")
	t.Setenv("SIGILUM_HOME", "")

	if got := resolveServiceAPIKey("demo-service-gateway", "default-key", ""); got != "scoped-key" {
		t.Fatalf("expected scoped key, got %q", got)
	}
}

func TestResolveServiceAPIKeyFallsBackToFile(t *testing.T) {
	t.Setenv("SIGILUM_SERVICE_API_KEY_DEMO_SERVICE_GATEWAY", "")
	t.Setenv("SIGILUM_HOME", "")

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "service-api-key-demo-service-gateway")
	if err := os.WriteFile(keyFile, []byte("  file-key  \n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	if got := resolveServiceAPIKey("demo-service-gateway", "", tmp); got != "file-key" {
		t.Fatalf("expected file key, got %q", got)
	}
}

func TestResolveServiceAPIKeyPrefersFileOverDefault(t *testing.T) {
	t.Setenv("SIGILUM_SERVICE_API_KEY_DEMO_SERVICE_GATEWAY", "")
	t.Setenv("SIGILUM_HOME", "")

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "service-api-key-demo-service-gateway")
	if err := os.WriteFile(keyFile, []byte("file-key\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	if got := resolveServiceAPIKey("demo-service-gateway", "default-key", tmp); got != "file-key" {
		t.Fatalf("expected file key to override default key, got %q", got)
	}
}

func TestResolveServiceAPIKeyFallsBackToDefaultWithoutFile(t *testing.T) {
	t.Setenv("SIGILUM_SERVICE_API_KEY_DEMO_SERVICE_GATEWAY", "")
	t.Setenv("SIGILUM_HOME", "")

	if got := resolveServiceAPIKey("demo-service-gateway", "default-key", t.TempDir()); got != "default-key" {
		t.Fatalf("expected default key fallback, got %q", got)
	}
}

func TestResolveServiceAPIKeyRejectsUnsafeIDForFileLookup(t *testing.T) {
	t.Setenv("SIGILUM_SERVICE_API_KEY_DEFAULT", "")
	t.Setenv("SIGILUM_HOME", "")

	tmp := t.TempDir()
	if got := resolveServiceAPIKey("../escape", "", tmp); got != "" {
		t.Fatalf("expected empty key for unsafe id, got %q", got)
	}
}

func TestExtractSigilumIdentityRequiresSubject(t *testing.T) {
	headers := http.Header{}
	headers.Set(headerNamespace, "alice")
	headers.Set(headerAgentKey, "ed25519:test")

	_, _, _, err := extractSigilumIdentity(headers)
	if err == nil {
		t.Fatal("expected missing sigilum-subject error")
	}
}

func TestResolveMCPRouteList(t *testing.T) {
	connectionID, action, tool, ok := resolveMCPRoute("/mcp/linear/tools")
	if !ok {
		t.Fatal("expected valid mcp list route")
	}
	if connectionID != "linear" || action != "list" || tool != "" {
		t.Fatalf("unexpected route parse: connection=%s action=%s tool=%s", connectionID, action, tool)
	}
}

func TestResolveMCPRouteCall(t *testing.T) {
	connectionID, action, tool, ok := resolveMCPRoute("/mcp/linear/tools/linear.searchIssues/call")
	if !ok {
		t.Fatal("expected valid mcp call route")
	}
	if connectionID != "linear" || action != "call" || tool != "linear.searchIssues" {
		t.Fatalf("unexpected route parse: connection=%s action=%s tool=%s", connectionID, action, tool)
	}
}

func TestShouldAutoDiscoverMCPTools(t *testing.T) {
	cases := []struct {
		name     string
		conn     connectors.Connection
		expected bool
	}{
		{
			name: "no tools and no discovery timestamp",
			conn: connectors.Connection{
				Protocol: connectors.ConnectionProtocolMCP,
				MCPDiscovery: connectors.MCPDiscovery{
					Tools: nil,
				},
			},
			expected: true,
		},
		{
			name: "no tools after prior discovery",
			conn: connectors.Connection{
				Protocol: connectors.ConnectionProtocolMCP,
				MCPDiscovery: connectors.MCPDiscovery{
					Tools:            nil,
					LastDiscoveredAt: time.Date(2026, time.February, 19, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: false,
		},
		{
			name: "discovered tools present",
			conn: connectors.Connection{
				Protocol: connectors.ConnectionProtocolMCP,
				MCPDiscovery: connectors.MCPDiscovery{
					Tools: []connectors.MCPTool{
						{Name: "search"},
					},
					LastDiscoveredAt: time.Date(2026, time.February, 19, 0, 0, 0, 0, time.UTC),
				},
			},
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAutoDiscoverMCPTools(tc.conn); got != tc.expected {
				t.Fatalf("expected %t, got %t", tc.expected, got)
			}
		})
	}
}

func TestResolveToolArgumentsWrappedAndDirect(t *testing.T) {
	wrapped, err := resolveToolArguments([]byte(`{"arguments":{"query":"auth"}}`))
	if err != nil {
		t.Fatalf("resolve wrapped arguments failed: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(wrapped), []byte(`{"query":"auth"}`)) {
		t.Fatalf("unexpected wrapped args: %s", string(wrapped))
	}

	direct, err := resolveToolArguments([]byte(`{"query":"auth"}`))
	if err != nil {
		t.Fatalf("resolve direct arguments failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(direct, &parsed); err != nil {
		t.Fatalf("expected JSON arguments, got %v", err)
	}
	if parsed["query"] != "auth" {
		t.Fatalf("unexpected direct args payload: %#v", parsed)
	}
}

func TestValidateSigilumAuthHeadersRejectsDuplicates(t *testing.T) {
	headers := http.Header{}
	headers.Add("Signature-Input", "sig1=(\"@method\")")
	headers.Add("Signature-Input", "sig1=(\"@target-uri\")")

	err := validateSigilumAuthHeaders(headers)
	if err == nil {
		t.Fatal("expected duplicate signature-input header to be rejected")
	}
}

func TestReadLimitedRequestBodyRejectsTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/proxy/demo", io.NopCloser(strings.NewReader("abcdef")))
	body, err := readLimitedRequestBody(req, 4)
	if err == nil {
		t.Fatalf("expected body limit error, got body=%q", string(body))
	}
	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("expected errRequestBodyTooLarge, got %v", err)
	}
}

func TestReadJSONBodyRejectsTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/connections", io.NopCloser(strings.NewReader(`{"key":"abcdefghijklmnopqrstuvwxyz"}`)))
	var payload map[string]any

	err := readJSONBody(req, &payload, 16)
	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("expected errRequestBodyTooLarge, got %v", err)
	}
}

func TestSetCORSHeadersSkipsDisallowedOrigin(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.Header.Set("Origin", "https://evil.example")

	setCORSHeaders(recorder, req, map[string]struct{}{
		"https://allowed.example": {},
	})

	headers := recorder.Header()
	if got := headers.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no allow-origin header for disallowed origin, got %q", got)
	}
	if got := headers.Get("Access-Control-Allow-Methods"); got != "" {
		t.Fatalf("expected no allow-methods header for disallowed origin, got %q", got)
	}
}

func TestSetCORSHeadersSetsHeadersForAllowedOrigin(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/connections", nil)
	req.Header.Set("Origin", "https://allowed.example")

	setCORSHeaders(recorder, req, map[string]struct{}{
		"https://allowed.example": {},
	})

	headers := recorder.Header()
	if got := headers.Get("Access-Control-Allow-Origin"); got != "https://allowed.example" {
		t.Fatalf("expected allow-origin for allowed origin, got %q", got)
	}
	if got := headers.Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatalf("expected allow-methods header for allowed origin")
	}
}

func TestWithRequestIDSetsGeneratedHeader(t *testing.T) {
	handler := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestID := requestIDFromContext(r.Context()); requestID == "" {
			t.Fatalf("expected request id in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get(requestIDHeader); got == "" {
		t.Fatalf("expected %s header to be set", requestIDHeader)
	}
}

func TestWithRequestIDPreservesIncomingHeader(t *testing.T) {
	handler := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestID := requestIDFromContext(r.Context()); requestID != "req-from-client" {
			t.Fatalf("expected context request id to preserve incoming value, got %q", requestID)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(requestIDHeader, "req-from-client")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get(requestIDHeader); got != "req-from-client" {
		t.Fatalf("expected response header to preserve incoming request id, got %q", got)
	}
}

func TestWriteProxyAuthRequiredMarkdown(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeProxyAuthRequiredMarkdown(recorder, proxyAuthRequiredMarkdownInput{
		Namespace: "alice",
		Subject:   "agent-main",
		PublicKey: "ed25519:abc123",
		Service:   "sigilum-secure-linear",
		RemoteIP:  "203.0.113.10",
		ClaimRegistration: claimRegistrationAttempt{
			Enabled: true,
			Result: claimcache.SubmitClaimResult{
				HTTPStatus: http.StatusCreated,
				ClaimID:    "cl_test_123",
				Status:     "pending",
				Message:    "Access request submitted.",
			},
		},
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d", recorder.Code)
	}
	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/markdown") {
		t.Fatalf("expected markdown response content-type, got %q", contentType)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "AUTH_FORBIDDEN") {
		t.Fatalf("expected AUTH_FORBIDDEN marker in markdown body")
	}
	if !strings.Contains(body, "HTTP 403") {
		t.Fatalf("expected explicit HTTP 403 marker in markdown body")
	}
	if !strings.Contains(body, "SECURE ACCESS BLOCKED") {
		t.Fatalf("expected warning banner in markdown body")
	}
	if !strings.Contains(body, "revoked/expired") {
		t.Fatalf("expected revoked/expired guidance in markdown body")
	}
	if !strings.Contains(body, "cl_test_123") {
		t.Fatalf("expected claim id details in markdown body")
	}
}

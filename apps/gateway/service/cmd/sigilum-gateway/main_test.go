package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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

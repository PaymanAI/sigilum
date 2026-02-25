package main

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestSanitizeDecisionValueRedactsSensitiveFields(t *testing.T) {
	got := sanitizeDecisionValue("authorization", "Bearer super-secret-token")
	if got != "[redacted]" {
		t.Fatalf("expected redacted authorization value, got %#v", got)
	}

	got = sanitizeDecisionValue("api_key", "sk_live_123")
	if got != "[redacted]" {
		t.Fatalf("expected redacted api_key value, got %#v", got)
	}
}

func TestSanitizeDecisionValueHashesIdentityFields(t *testing.T) {
	got := sanitizeDecisionValue("namespace", "alice")
	hash, ok := got.(string)
	if !ok {
		t.Fatalf("expected hashed namespace string, got %#v", got)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected namespace hash prefix, got %q", hash)
	}
	if strings.Contains(hash, "alice") {
		t.Fatalf("expected namespace to be hashed, got %q", hash)
	}
}

func TestSanitizeDecisionValueDoesNotHashSubject(t *testing.T) {
	got := sanitizeDecisionValue("subject", "customer-12345")
	subject, ok := got.(string)
	if !ok {
		t.Fatalf("expected subject string, got %#v", got)
	}
	if subject != "customer-12345" {
		t.Fatalf("expected cleartext subject, got %q", subject)
	}
}

func TestConstructDID(t *testing.T) {
	did := constructDID("mfs", "narmi", "davis-agent", "customer-12345")
	if did != "did:sigilum:mfs:narmi#davis-agent#customer-12345" {
		t.Fatalf("unexpected did with subject: %q", did)
	}

	did = constructDID("tyllenb", "github", "hamza", "tyllenb")
	if did != "did:sigilum:tyllenb:github#hamza" {
		t.Fatalf("unexpected did namespace fallback: %q", did)
	}
}

func TestDIDAgentFragmentFromPublicKey(t *testing.T) {
	fragment := didAgentFragment("ed25519:abcDEF1234567890+/==")
	if strings.Contains(fragment, ":") || strings.Contains(fragment, "+") || strings.Contains(fragment, "/") {
		t.Fatalf("expected sanitized agent fragment, got %q", fragment)
	}
	if fragment == "" {
		t.Fatal("expected non-empty agent fragment")
	}
}

func TestSanitizeDecisionValueMasksIP(t *testing.T) {
	if got := sanitizeDecisionValue("remote_ip", "203.0.113.10"); got != "203.0.113.0/24" {
		t.Fatalf("expected masked ipv4 value, got %#v", got)
	}

	if got := sanitizeDecisionValue("remote_ip", "2001:db8::1"); got != "2001:db8::/64" {
		t.Fatalf("expected masked ipv6 value, got %#v", got)
	}

	if got := sanitizeDecisionValue("remote_ip", "203.0.113.10:44123"); got != "203.0.113.0/24" {
		t.Fatalf("expected masked host:port value, got %#v", got)
	}
}

func TestSanitizeDecisionValueRecursivelySanitizesNestedFields(t *testing.T) {
	got := sanitizeDecisionValue("context", map[string]any{
		"authorization": "Bearer nested-token",
		"namespace":     "alice",
		"remote_ip":     "203.0.113.10",
		"nested": map[string]any{
			"api_key": "sk_live_nested",
		},
	})

	payload, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map payload, got %#v", got)
	}
	if payload["authorization"] != "[redacted]" {
		t.Fatalf("expected nested authorization to be redacted, got %#v", payload["authorization"])
	}
	namespace, _ := payload["namespace"].(string)
	if !strings.HasPrefix(namespace, "sha256:") {
		t.Fatalf("expected nested namespace to be hashed, got %#v", payload["namespace"])
	}
	if payload["remote_ip"] != "203.0.113.0/24" {
		t.Fatalf("expected nested remote_ip to be masked, got %#v", payload["remote_ip"])
	}

	nested, ok := payload["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map payload, got %#v", payload["nested"])
	}
	if nested["api_key"] != "[redacted]" {
		t.Fatalf("expected nested api_key to be redacted, got %#v", nested["api_key"])
	}
}

func TestLogGatewayDecisionWritesJSONAndRedactsFields(t *testing.T) {
	var buffer bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	logGatewayDecision("proxy_auth_denied", map[string]any{
		"request_id":    "req-test",
		"remote_ip":     "203.0.113.10",
		"namespace":     "alice",
		"authorization": "Bearer hidden-token",
		"status":        403,
	})

	line := strings.TrimSpace(buffer.String())
	if line == "" {
		t.Fatal("expected log output")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("expected JSON log output, got decode error: %v line=%q", err, line)
	}

	if payload["event"] != "proxy_auth_denied" {
		t.Fatalf("expected event proxy_auth_denied, got %#v", payload["event"])
	}
	if payload["remote_ip"] != "203.0.113.0/24" {
		t.Fatalf("expected masked remote_ip, got %#v", payload["remote_ip"])
	}
	namespace, _ := payload["namespace"].(string)
	if !strings.HasPrefix(namespace, "sha256:") {
		t.Fatalf("expected hashed namespace, got %#v", payload["namespace"])
	}
	if payload["authorization"] != "[redacted]" {
		t.Fatalf("expected redacted authorization, got %#v", payload["authorization"])
	}
	if payload["status"] != float64(403) {
		t.Fatalf("expected numeric status, got %#v", payload["status"])
	}
}

func TestLogGatewayDecisionRedactsNestedMapFields(t *testing.T) {
	var buffer bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	logGatewayDecision("proxy_auth_denied", map[string]any{
		"request_id": "req-nested",
		"context": map[string]any{
			"authorization": "Bearer nested-secret",
			"api_key":       "sk_live_nested",
			"namespace":     "alice",
		},
	})

	line := strings.TrimSpace(buffer.String())
	if line == "" {
		t.Fatal("expected log output")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("expected JSON log output, got decode error: %v line=%q", err, line)
	}

	contextValue, ok := payload["context"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested context map, got %#v", payload["context"])
	}
	if contextValue["authorization"] != "[redacted]" {
		t.Fatalf("expected nested authorization to be redacted, got %#v", contextValue["authorization"])
	}
	if contextValue["api_key"] != "[redacted]" {
		t.Fatalf("expected nested api_key to be redacted, got %#v", contextValue["api_key"])
	}
	namespace, _ := contextValue["namespace"].(string)
	if !strings.HasPrefix(namespace, "sha256:") {
		t.Fatalf("expected nested namespace to be hashed, got %#v", contextValue["namespace"])
	}
}

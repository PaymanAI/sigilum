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

package sigilum

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	tmp := t.TempDir()

	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	signed, err := SignHTTPRequest(identity, SignRequestInput{
		URL:    "https://api.sigilum.local/v1/namespaces/alice/claims",
		Method: "POST",
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: []byte(`{"action":"approve"}`),
	})
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	if got := signed.Headers["sigilum-subject"]; got != "alice" {
		t.Fatalf("expected default sigilum-subject alice, got %q", got)
	}

	verified := VerifyHTTPSignature(VerifySignatureInput{
		URL:               signed.URL,
		Method:            signed.Method,
		Headers:           signed.Headers,
		Body:              signed.Body,
		ExpectedNamespace: "alice",
	})
	if !verified.Valid {
		t.Fatalf("expected valid signature, got reason: %s", verified.Reason)
	}
	if verified.Subject != "alice" {
		t.Fatalf("expected default subject alice, got %q", verified.Subject)
	}
}

func TestVerifyFailsOnBodyTamper(t *testing.T) {
	tmp := t.TempDir()
	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	signed, err := SignHTTPRequest(identity, SignRequestInput{
		URL:    "https://api.sigilum.local/v1/namespaces/alice/claims",
		Method: "POST",
		Body:   []byte(`{"action":"approve"}`),
	})
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	verified := VerifyHTTPSignature(VerifySignatureInput{
		URL:               signed.URL,
		Method:            signed.Method,
		Headers:           signed.Headers,
		Body:              []byte(`{"action":"tampered"}`),
		ExpectedNamespace: "alice",
	})
	if verified.Valid {
		t.Fatalf("expected invalid signature when body is tampered")
	}
	if verified.Code != "SIG_CONTENT_DIGEST_MISMATCH" {
		t.Fatalf("expected SIG_CONTENT_DIGEST_MISMATCH, got %q", verified.Code)
	}
}

func TestVerifyFailsOnSubjectMismatch(t *testing.T) {
	tmp := t.TempDir()
	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	signed, err := SignHTTPRequest(identity, SignRequestInput{
		URL:     "https://api.sigilum.local/v1/namespaces/alice/claims",
		Method:  "GET",
		Subject: "user-123",
	})
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}

	verified := VerifyHTTPSignature(VerifySignatureInput{
		URL:               signed.URL,
		Method:            signed.Method,
		Headers:           signed.Headers,
		ExpectedNamespace: "alice",
		ExpectedSubject:   "user-999",
	})
	if verified.Valid {
		t.Fatal("expected invalid signature due to subject mismatch")
	}
	if verified.Code != "SIG_EXPECTED_SUBJECT_MISMATCH" {
		t.Fatalf("expected SIG_EXPECTED_SUBJECT_MISMATCH, got %q", verified.Code)
	}
}

func TestVerifyFailsOnInvalidSignedComponentSet(t *testing.T) {
	tmp := t.TempDir()
	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	signed, err := SignHTTPRequest(identity, SignRequestInput{
		URL:    "https://api.sigilum.local/v1/namespaces/alice/claims",
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	signatureInput := signed.Headers["signature-input"]
	if signatureInput == "" {
		t.Fatal("missing signature-input header")
	}
	signed.Headers["signature-input"] = strings.Replace(signatureInput, "\"sigilum-agent-cert\"", "", 1)

	verified := VerifyHTTPSignature(VerifySignatureInput{
		URL:               signed.URL,
		Method:            signed.Method,
		Headers:           signed.Headers,
		ExpectedNamespace: "alice",
	})
	if verified.Valid {
		t.Fatal("expected invalid signature due to signed component profile")
	}
	if verified.Code != "SIG_SIGNED_COMPONENTS_INVALID" {
		t.Fatalf("expected SIG_SIGNED_COMPONENTS_INVALID, got %q", verified.Code)
	}
	if !strings.Contains(strings.ToLower(verified.Reason), "component set") {
		t.Fatalf("expected component-set error, got: %s", verified.Reason)
	}
}

func TestVerifyAllowsSignedAgentIDComponentSet(t *testing.T) {
	tmp := t.TempDir()
	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	buildSignedWithAgentID := func(method string, body []byte) SignedRequest {
		signed, signErr := SignHTTPRequest(identity, SignRequestInput{
			URL:     "https://api.sigilum.local/v1/namespaces/alice/claims",
			Method:  method,
			Body:    body,
			Subject: "user-123",
			Headers: map[string]string{
				"sigilum-agent-id": "main",
			},
		})
		if signErr != nil {
			t.Fatalf("sign request: %v", signErr)
		}
		signed.Headers["sigilum-agent-id"] = "main"

		parsed, parseErr := parseSignatureInputHeader(signed.Headers["signature-input"])
		if parseErr != nil {
			t.Fatalf("parse signature input: %v", parseErr)
		}
		components := []string{"@method", "@target-uri", "sigilum-namespace", "sigilum-subject", "sigilum-agent-id", "sigilum-agent-key", "sigilum-agent-cert"}
		if len(body) > 0 {
			components = []string{"@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-subject", "sigilum-agent-id", "sigilum-agent-key", "sigilum-agent-cert"}
		}
		sigParams := signatureParams(components, parsed.Created, parsed.KeyID, parsed.Nonce)
		base, baseErr := signingBase(components, normalizeMethod(signed.Method), normalizeTargetURI(signed.URL), normalizeHeaders(signed.Headers), sigParams)
		if baseErr != nil {
			t.Fatalf("signing base: %v", baseErr)
		}
		private := ed25519.NewKeyFromSeed(identity.PrivateKey)
		signature := ed25519.Sign(private, base)
		signed.Headers["signature-input"] = "sig1=" + sigParams
		signed.Headers["signature"] = "sig1=:" + base64.StdEncoding.EncodeToString(signature) + ":"
		return signed
	}

	t.Run("no body", func(t *testing.T) {
		signed := buildSignedWithAgentID("GET", nil)
		verified := VerifyHTTPSignature(VerifySignatureInput{
			URL:               signed.URL,
			Method:            signed.Method,
			Headers:           signed.Headers,
			ExpectedNamespace: "alice",
			ExpectedSubject:   "user-123",
		})
		if !verified.Valid {
			t.Fatalf("expected valid signature with sigilum-agent-id, got: %s (%s)", verified.Code, verified.Reason)
		}
	})

	t.Run("with body", func(t *testing.T) {
		signed := buildSignedWithAgentID("POST", []byte(`{"action":"approve"}`))
		verified := VerifyHTTPSignature(VerifySignatureInput{
			URL:               signed.URL,
			Method:            signed.Method,
			Headers:           signed.Headers,
			Body:              signed.Body,
			ExpectedNamespace: "alice",
			ExpectedSubject:   "user-123",
		})
		if !verified.Valid {
			t.Fatalf("expected valid signature with sigilum-agent-id body profile, got: %s (%s)", verified.Code, verified.Reason)
		}
	})
}

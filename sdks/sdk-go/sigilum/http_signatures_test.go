package sigilum

import "testing"

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
}

package sigilum

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureIdentityRecord struct {
	Namespace string `json:"namespace"`
	DID       string `json:"did"`
	KeyID     string `json:"keyId"`
}

func TestInitIdentityCreatesAndReloads(t *testing.T) {
	tmp := t.TempDir()

	first, err := InitIdentity(InitIdentityOptions{
		Namespace: "alice",
		HomeDir:   tmp,
	})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}
	if !first.Created {
		t.Fatalf("expected first init to create identity")
	}

	second, err := InitIdentity(InitIdentityOptions{
		Namespace: "alice",
		HomeDir:   tmp,
	})
	if err != nil {
		t.Fatalf("init identity (second): %v", err)
	}
	if second.Created {
		t.Fatalf("expected second init to load existing identity")
	}
	if first.PublicKey != second.PublicKey {
		t.Fatalf("expected same public key, got %q and %q", first.PublicKey, second.PublicKey)
	}

	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if identity.Namespace != "alice" {
		t.Fatalf("unexpected namespace: %s", identity.Namespace)
	}
}

func TestListNamespaces(t *testing.T) {
	tmp := t.TempDir()

	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init alice: %v", err)
	}
	_, err = InitIdentity(InitIdentityOptions{Namespace: "bob", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init bob: %v", err)
	}

	namespaces, err := ListNamespaces(tmp)
	if err != nil {
		t.Fatalf("list namespaces: %v", err)
	}
	if len(namespaces) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(namespaces))
	}
	if namespaces[0] != "alice" || namespaces[1] != "bob" {
		t.Fatalf("unexpected namespaces: %#v", namespaces)
	}
}

func TestLoadIdentitySharedV1Fixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "identity-record-v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture fixtureIdentityRecord
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	tmp := t.TempDir()
	targetDir := filepath.Join(tmp, "identities", fixture.Namespace)
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "identity.json"), raw, 0o600); err != nil {
		t.Fatalf("write fixture identity: %v", err)
	}

	identity, err := LoadIdentity(LoadIdentityOptions{
		Namespace: fixture.Namespace,
		HomeDir:   tmp,
	})
	if err != nil {
		t.Fatalf("load identity fixture: %v", err)
	}
	if identity.Namespace != fixture.Namespace {
		t.Fatalf("expected namespace %q, got %q", fixture.Namespace, identity.Namespace)
	}
	if identity.DID != fixture.DID {
		t.Fatalf("expected did %q, got %q", fixture.DID, identity.DID)
	}
	if identity.KeyID != fixture.KeyID {
		t.Fatalf("expected key id %q, got %q", fixture.KeyID, identity.KeyID)
	}
}

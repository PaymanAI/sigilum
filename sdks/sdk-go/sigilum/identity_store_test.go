package sigilum

import "testing"

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

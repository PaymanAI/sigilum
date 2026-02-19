package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNonceReplayCachePersistsAcrossRestart(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "nonce-replay-cache.json")
	now := time.Now().UTC()

	cache := newNonceReplayCache(5*time.Minute, storePath)
	if cache.Seen("alice", "nonce-1", now) {
		t.Fatal("expected first nonce use to be accepted")
	}

	reloaded := newNonceReplayCache(5*time.Minute, storePath)
	if !reloaded.Seen("alice", "nonce-1", now.Add(2*time.Second)) {
		t.Fatal("expected persisted nonce to be detected as replay after restart")
	}
}

func TestNonceReplayCacheIgnoresExpiredPersistedEntries(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "nonce-replay-cache.json")
	state := persistedNonceState{
		Version: nonceReplayStateVersion,
		Entries: []persistedNonceEntry{
			{
				Key:       "alice\x00expired-nonce",
				ExpiresAt: time.Now().UTC().Add(-time.Minute),
			},
		},
	}

	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal nonce state: %v", err)
	}
	if err := os.WriteFile(storePath, payload, 0o600); err != nil {
		t.Fatalf("write nonce state: %v", err)
	}

	cache := newNonceReplayCache(5*time.Minute, storePath)
	if cache.Seen("alice", "expired-nonce", time.Now().UTC()) {
		t.Fatal("expected expired persisted nonce to be treated as unused")
	}
}

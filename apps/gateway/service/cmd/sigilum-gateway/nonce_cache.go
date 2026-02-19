package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const nonceReplayStateVersion = 1

type nonceReplayCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	nonces    map[string]time.Time
	lastSweep time.Time
	storePath string
}

type persistedNonceEntry struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
}

type persistedNonceState struct {
	Version int                   `json:"version"`
	Entries []persistedNonceEntry `json:"entries"`
}

func newNonceReplayCache(ttl time.Duration, storePath string) *nonceReplayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	cache := &nonceReplayCache{
		ttl:       ttl,
		nonces:    map[string]time.Time{},
		storePath: strings.TrimSpace(storePath),
	}
	cache.loadPersistedState(time.Now().UTC())
	return cache
}

func (c *nonceReplayCache) Seen(namespace string, nonce string, now time.Time) bool {
	namespace = strings.TrimSpace(namespace)
	nonce = strings.TrimSpace(nonce)
	if namespace == "" || nonce == "" {
		return false
	}
	key := namespace + "\x00" + nonce
	expiresAt := now.Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	persistRequired := false
	if now.Sub(c.lastSweep) > time.Minute {
		if c.sweepExpiredLocked(now) {
			persistRequired = true
		}
		c.lastSweep = now
	}

	if existing, ok := c.nonces[key]; ok && existing.After(now) {
		if persistRequired {
			c.persistStateLocked(now)
		}
		return true
	}

	c.nonces[key] = expiresAt
	persistRequired = true
	if persistRequired {
		c.persistStateLocked(now)
	}
	return false
}

func (c *nonceReplayCache) sweepExpiredLocked(now time.Time) bool {
	changed := false
	for key, expiry := range c.nonces {
		if !expiry.After(now) {
			delete(c.nonces, key)
			changed = true
		}
	}
	return changed
}

func (c *nonceReplayCache) loadPersistedState(now time.Time) {
	if c.storePath == "" {
		return
	}
	data, err := os.ReadFile(c.storePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("warning: failed to read nonce replay cache %s: %v", c.storePath, err)
		return
	}

	var state persistedNonceState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("warning: failed to decode nonce replay cache %s: %v", c.storePath, err)
		return
	}
	if state.Version != nonceReplayStateVersion {
		log.Printf(
			"warning: unsupported nonce replay cache version=%d path=%s expected=%d",
			state.Version,
			c.storePath,
			nonceReplayStateVersion,
		)
		return
	}

	loaded := 0
	for _, entry := range state.Entries {
		if strings.TrimSpace(entry.Key) == "" || !entry.ExpiresAt.After(now) {
			continue
		}
		c.nonces[entry.Key] = entry.ExpiresAt
		loaded++
	}
	if loaded > 0 {
		log.Printf("loaded %d nonce replay entries from %s", loaded, c.storePath)
	}
}

func (c *nonceReplayCache) persistStateLocked(now time.Time) {
	if c.storePath == "" {
		return
	}

	entries := make([]persistedNonceEntry, 0, len(c.nonces))
	for key, expiresAt := range c.nonces {
		if !expiresAt.After(now) {
			continue
		}
		entries = append(entries, persistedNonceEntry{
			Key:       key,
			ExpiresAt: expiresAt,
		})
	}

	if len(entries) == 0 {
		if err := os.Remove(c.storePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: failed to remove nonce replay cache %s: %v", c.storePath, err)
		}
		return
	}

	state := persistedNonceState{
		Version: nonceReplayStateVersion,
		Entries: entries,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		log.Printf("warning: failed to encode nonce replay cache %s: %v", c.storePath, err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(c.storePath), 0o700); err != nil {
		log.Printf("warning: failed to create nonce replay cache dir for %s: %v", c.storePath, err)
		return
	}

	tempPath := c.storePath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		log.Printf("warning: failed to write nonce replay cache temp file %s: %v", tempPath, err)
		return
	}
	if err := os.Rename(tempPath, c.storePath); err != nil {
		log.Printf("warning: failed to persist nonce replay cache %s: %v", c.storePath, err)
		_ = os.Remove(tempPath)
	}
}

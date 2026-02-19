package claims

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"sigilum.local/sdk-go/sigilum"
)

func TestIsApprovedCachesWithinTTL(t *testing.T) {
	tmp := t.TempDir()
	if _, err := sigilum.InitIdentity(sigilum.InitIdentityOptions{Namespace: "gateway", HomeDir: tmp}); err != nil {
		t.Fatalf("init signer identity: %v", err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/claims" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer svc-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"claims": []map[string]any{
				{
					"namespace":  "alice",
					"public_key": "ed25519:pk1",
				},
			},
			"pagination": map[string]any{
				"has_more": false,
			},
		})
	}))
	defer server.Close()

	cache, err := NewCache(CacheConfig{
		APIBaseURL:      server.URL,
		SignerNamespace: "gateway",
		SignerHomeDir:   tmp,
		RequestTimeout:  2 * time.Second,
		CacheTTL:        100 * time.Millisecond,
		RefreshInterval: 50 * time.Millisecond,
		ResolveServiceAPIKey: func(service string) string {
			return "svc-key"
		},
	})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	defer cache.Close()

	ok, err := cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk1")
	if err != nil {
		t.Fatalf("first IsApproved failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected approved on first lookup")
	}

	ok, err = cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk1")
	if err != nil {
		t.Fatalf("second IsApproved failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected approved on second lookup")
	}

	if calls.Load() != 1 {
		t.Fatalf("expected one upstream fetch within ttl, got %d", calls.Load())
	}

	time.Sleep(130 * time.Millisecond)
	ok, err = cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk1")
	if err != nil {
		t.Fatalf("third IsApproved failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected approved after ttl refresh")
	}
	if calls.Load() < 2 {
		t.Fatalf("expected second upstream fetch after ttl expiry, got %d", calls.Load())
	}
}

func TestCacheBackgroundRefreshForActiveService(t *testing.T) {
	tmp := t.TempDir()
	if _, err := sigilum.InitIdentity(sigilum.InitIdentityOptions{Namespace: "gateway", HomeDir: tmp}); err != nil {
		t.Fatalf("init signer identity: %v", err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/claims" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"claims": []map[string]any{
				{
					"namespace":  "alice",
					"public_key": "ed25519:pk1",
				},
			},
			"pagination": map[string]any{
				"has_more": false,
			},
		})
	}))
	defer server.Close()

	cache, err := NewCache(CacheConfig{
		APIBaseURL:      server.URL,
		SignerNamespace: "gateway",
		SignerHomeDir:   tmp,
		RequestTimeout:  2 * time.Second,
		CacheTTL:        90 * time.Millisecond,
		RefreshInterval: 20 * time.Millisecond,
		ResolveServiceAPIKey: func(service string) string {
			return "svc-key"
		},
	})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	cache.Start()
	defer cache.Close()

	ok, err := cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk1")
	if err != nil {
		t.Fatalf("initial IsApproved failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected approved on initial lookup")
	}

	initialCalls := calls.Load()
	time.Sleep(170 * time.Millisecond)
	refreshedCalls := calls.Load()
	if refreshedCalls <= initialCalls {
		t.Fatalf("expected background refresh to increase upstream calls, before=%d after=%d", initialCalls, refreshedCalls)
	}
}

func TestIsApprovedCapsApprovedClaimsFetch(t *testing.T) {
	tmp := t.TempDir()
	if _, err := sigilum.InitIdentity(sigilum.InitIdentityOptions{Namespace: "gateway", HomeDir: tmp}); err != nil {
		t.Fatalf("init signer identity: %v", err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/claims" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)

		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		claims := []map[string]any{}
		hasMore := false
		switch offset {
		case 0:
			claims = []map[string]any{
				{"namespace": "alice", "public_key": "ed25519:pk1"},
				{"namespace": "alice", "public_key": "ed25519:pk2"},
			}
			hasMore = true
		case 2:
			claims = []map[string]any{
				{"namespace": "alice", "public_key": "ed25519:pk3"},
				{"namespace": "alice", "public_key": "ed25519:pk4"},
			}
			hasMore = true
		default:
			claims = []map[string]any{
				{"namespace": "alice", "public_key": "ed25519:pk5"},
			}
			hasMore = false
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"claims": claims,
			"pagination": map[string]any{
				"has_more": hasMore,
			},
		})
	}))
	defer server.Close()

	cache, err := NewCache(CacheConfig{
		APIBaseURL:        server.URL,
		SignerNamespace:   "gateway",
		SignerHomeDir:     tmp,
		RequestTimeout:    2 * time.Second,
		CacheTTL:          100 * time.Millisecond,
		RefreshInterval:   50 * time.Millisecond,
		MaxApprovedClaims: 3,
		ResolveServiceAPIKey: func(service string) string {
			return "svc-key"
		},
	})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	defer cache.Close()

	ok, err := cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk3")
	if err != nil {
		t.Fatalf("IsApproved failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected pk3 to be included before cap")
	}

	ok, err = cache.IsApproved(context.Background(), "svc-a", "alice", "ed25519:pk4")
	if err != nil {
		t.Fatalf("IsApproved failed: %v", err)
	}
	if ok {
		t.Fatalf("expected pk4 to be excluded after cap")
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 paged calls before cap, got %d", got)
	}
}

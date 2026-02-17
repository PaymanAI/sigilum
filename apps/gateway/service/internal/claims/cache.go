package claims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sigilum.local/sdk-go/sigilum"
)

const (
	defaultCacheTTL         = 30 * time.Second
	defaultRefreshInterval  = 10 * time.Second
	defaultRequestTimeout   = 30 * time.Second
	maxInactiveRefreshSkips = 2
)

type CacheConfig struct {
	APIBaseURL           string
	SignerNamespace      string
	SignerHomeDir        string
	RequestTimeout       time.Duration
	CacheTTL             time.Duration
	RefreshInterval      time.Duration
	ResolveServiceAPIKey func(service string) string
	Logger               func(format string, args ...any)
}

type approvalSnapshot struct {
	approved   map[string]struct{}
	expiresAt  time.Time
	lastAccess time.Time
}

type refreshState struct {
	done chan struct{}
	err  error
}

type Cache struct {
	baseURL              string
	bindings             *sigilum.SigilumBindings
	resolveServiceAPIKey func(service string) string
	logger               func(format string, args ...any)
	cacheTTL             time.Duration
	refreshInterval      time.Duration
	requestTimeout       time.Duration

	once      sync.Once
	closeOnce sync.Once
	stopCh    chan struct{}
	wg        sync.WaitGroup

	mu        sync.RWMutex
	snapshots map[string]approvalSnapshot
	inflight  map[string]*refreshState
}

func NewCache(cfg CacheConfig) (*Cache, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.sigilum.id"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = func(string, ...any) {}
	}

	requestTimeout := cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = defaultRefreshInterval
	}
	if refreshInterval > cacheTTL {
		refreshInterval = cacheTTL
	}

	httpClient := http.DefaultClient
	httpClient = &http.Client{Timeout: requestTimeout}

	bindings, err := sigilum.Certify(sigilum.CertifyOptions{
		Namespace:  cfg.SignerNamespace,
		HomeDir:    cfg.SignerHomeDir,
		APIBaseURL: baseURL,
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Sigilum signer for claims cache: %w", err)
	}

	return &Cache{
		baseURL:              baseURL,
		bindings:             bindings,
		resolveServiceAPIKey: cfg.ResolveServiceAPIKey,
		logger:               logger,
		cacheTTL:             cacheTTL,
		refreshInterval:      refreshInterval,
		requestTimeout:       requestTimeout,
		stopCh:               make(chan struct{}),
		snapshots:            make(map[string]approvalSnapshot, 8),
		inflight:             make(map[string]*refreshState, 8),
	}, nil
}

func (c *Cache) Start() {
	c.once.Do(func() {
		c.logger(
			"claims cache initialized ttl=%s refresh_interval=%s timeout=%s",
			c.cacheTTL,
			c.refreshInterval,
			c.requestTimeout,
		)
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.runBackgroundRefresh()
		}()
	})
}

func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		close(c.stopCh)
		c.wg.Wait()
	})
}

func (c *Cache) RefreshService(ctx context.Context, service string) error {
	service = strings.TrimSpace(service)
	if service == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	if existing, ok := c.inflight[service]; ok {
		done := existing.done
		c.mu.Unlock()
		select {
		case <-done:
			return existing.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	state := &refreshState{done: make(chan struct{})}
	c.inflight[service] = state

	now := time.Now().UTC()
	snapshot := c.snapshots[service]
	snapshot.lastAccess = now
	c.snapshots[service] = snapshot
	c.mu.Unlock()

	approved, err := c.loadApprovedClaims(ctx, service)
	refreshedAt := time.Now().UTC()

	c.mu.Lock()
	if err == nil {
		next := c.snapshots[service]
		next.approved = approved
		next.expiresAt = refreshedAt.Add(c.cacheTTL)
		next.lastAccess = refreshedAt
		c.snapshots[service] = next
	}
	state.err = err
	close(state.done)
	delete(c.inflight, service)
	c.mu.Unlock()

	return err
}

func (c *Cache) IsApproved(ctx context.Context, service, namespace, publicKey string) (bool, error) {
	service = strings.TrimSpace(service)
	namespace = strings.TrimSpace(namespace)
	publicKey = strings.TrimSpace(publicKey)
	if service == "" || namespace == "" || publicKey == "" {
		return false, nil
	}

	if c.bindings == nil {
		return false, errors.New("claims cache signer is not configured")
	}
	now := time.Now().UTC()
	c.touchService(service, now)

	approval := claimCacheKey(namespace, publicKey)
	if approved, ok := c.lookupFresh(service, approval, now); ok {
		return approved, nil
	}

	if err := c.RefreshService(ctx, service); err != nil {
		return false, err
	}
	approved, _ := c.lookupFresh(service, approval, time.Now().UTC())
	return approved, nil
}

func (c *Cache) runBackgroundRefresh() {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.refreshActiveServices()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Cache) refreshActiveServices() {
	services := c.servicesDueForRefresh(time.Now().UTC())
	for _, service := range services {
		ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
		err := c.RefreshService(ctx, service)
		cancel()
		if err != nil {
			c.logger("claims cache background refresh failed service=%s err=%v", service, err)
		}
	}
}

func (c *Cache) servicesDueForRefresh(now time.Time) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	due := make([]string, 0, len(c.snapshots))
	for service, snapshot := range c.snapshots {
		if snapshot.lastAccess.IsZero() {
			continue
		}
		if now.Sub(snapshot.lastAccess) > c.cacheTTL*time.Duration(maxInactiveRefreshSkips) {
			continue
		}
		if snapshot.approved == nil || !snapshot.expiresAt.After(now.Add(c.refreshInterval)) {
			due = append(due, service)
		}
	}
	return due
}

func (c *Cache) loadApprovedClaims(ctx context.Context, service string) (map[string]struct{}, error) {
	if c.resolveServiceAPIKey == nil {
		return nil, errors.New("service API key resolver is not configured")
	}
	serviceAPIKey := strings.TrimSpace(c.resolveServiceAPIKey(service))
	if serviceAPIKey == "" {
		return nil, fmt.Errorf("service API key not configured for service %q", service)
	}

	approved := make(map[string]struct{}, 256)
	offset := 0
	const pageSize = 500
	for {
		claimsURL, err := url.Parse(c.baseURL + "/v1/namespaces/claims")
		if err != nil {
			return nil, fmt.Errorf("invalid claims URL: %w", err)
		}
		query := claimsURL.Query()
		query.Set("service", service)
		query.Set("limit", fmt.Sprintf("%d", pageSize))
		query.Set("offset", fmt.Sprintf("%d", offset))
		claimsURL.RawQuery = query.Encode()

		resp, err := c.bindings.Do(ctx, sigilum.SignRequestInput{
			URL:    claimsURL.String(),
			Method: "GET",
			Headers: map[string]string{
				"Authorization": "Bearer " + serviceAPIKey,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("claims lookup request failed: %w", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed reading claims lookup response: %w", readErr)
		}
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("claims lookup unavailable: HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return nil, fmt.Errorf("claims lookup unauthorized: HTTP %d", resp.StatusCode)
			}
			return nil, fmt.Errorf("claims lookup failed: HTTP %d", resp.StatusCode)
		}

		var payload struct {
			Claims []struct {
				Namespace string `json:"namespace"`
				PublicKey string `json:"public_key"`
			} `json:"claims"`
			Pagination struct {
				HasMore bool `json:"has_more"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("failed to decode claims lookup response: %w", err)
		}

		for _, claim := range payload.Claims {
			namespace := strings.TrimSpace(claim.Namespace)
			publicKey := strings.TrimSpace(claim.PublicKey)
			if namespace == "" || publicKey == "" {
				continue
			}
			approved[claimCacheKey(namespace, publicKey)] = struct{}{}
		}
		if !payload.Pagination.HasMore || len(payload.Claims) == 0 {
			return approved, nil
		}
		offset += len(payload.Claims)
	}
}

func (c *Cache) touchService(service string, now time.Time) {
	c.mu.Lock()
	snapshot := c.snapshots[service]
	snapshot.lastAccess = now
	c.snapshots[service] = snapshot
	c.mu.Unlock()
}

func (c *Cache) lookupFresh(service string, approvalKey string, now time.Time) (bool, bool) {
	c.mu.RLock()
	snapshot, ok := c.snapshots[service]
	if !ok || snapshot.approved == nil || !snapshot.expiresAt.After(now) {
		c.mu.RUnlock()
		return false, false
	}
	_, approved := snapshot.approved[approvalKey]
	c.mu.RUnlock()
	return approved, true
}

func claimCacheKey(namespace string, publicKey string) string {
	return namespace + "\x00" + publicKey
}

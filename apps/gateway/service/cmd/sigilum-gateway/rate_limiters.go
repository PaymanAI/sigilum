package main

import (
	"strings"
	"sync"
	"time"

	"sigilum.local/gateway/config"
)

const defaultRateLimiterWindow = time.Minute

type rateLimitCounter struct {
	windowStart time.Time
	count       int
}

type fixedWindowRateLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	lastPruned time.Time
	counters   map[string]rateLimitCounter
}

var (
	claimRegistrationRateLimiter = newFixedWindowRateLimiter(0, defaultRateLimiterWindow)
	mcpToolCallRateLimiter       = newFixedWindowRateLimiter(0, defaultRateLimiterWindow)
)

func newFixedWindowRateLimiter(limit int, window time.Duration) *fixedWindowRateLimiter {
	if window <= 0 {
		window = defaultRateLimiterWindow
	}
	return &fixedWindowRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]rateLimitCounter, 128),
	}
}

func (l *fixedWindowRateLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	normalizedKey := strings.TrimSpace(key)
	if normalizedKey == "" {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	windowStart := now.Truncate(l.window)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneStaleLocked(windowStart)

	counter := l.counters[normalizedKey]
	if !counter.windowStart.Equal(windowStart) {
		counter = rateLimitCounter{windowStart: windowStart}
	}
	if counter.count >= l.limit {
		l.counters[normalizedKey] = counter
		return false
	}
	counter.count++
	l.counters[normalizedKey] = counter
	return true
}

func (l *fixedWindowRateLimiter) pruneStaleLocked(currentWindowStart time.Time) {
	if l == nil {
		return
	}
	if !l.lastPruned.IsZero() && currentWindowStart.Sub(l.lastPruned) < l.window {
		return
	}
	cutoff := currentWindowStart.Add(-l.window)
	for key, counter := range l.counters {
		if counter.windowStart.Before(cutoff) {
			delete(l.counters, key)
		}
	}
	l.lastPruned = currentWindowStart
}

func configureGatewayRateLimiters(cfg config.Config) {
	claimRegistrationRateLimiter = newFixedWindowRateLimiter(cfg.ClaimRegistrationRateLimit, defaultRateLimiterWindow)
	mcpToolCallRateLimiter = newFixedWindowRateLimiter(cfg.MCPToolCallRateLimit, defaultRateLimiterWindow)
}

func rateLimitKey(connectionID string, namespace string) string {
	connection := strings.TrimSpace(strings.ToLower(connectionID))
	if connection == "" {
		connection = "_"
	}
	ns := strings.TrimSpace(strings.ToLower(namespace))
	if ns == "" {
		ns = "_"
	}
	return connection + "|" + ns
}

func allowClaimRegistration(connectionID string, namespace string) bool {
	return claimRegistrationRateLimiter.allow(rateLimitKey(connectionID, namespace), time.Now().UTC())
}

func allowMCPToolCall(connectionID string, namespace string) bool {
	return mcpToolCallRateLimiter.allow(rateLimitKey(connectionID, namespace), time.Now().UTC())
}

package main

import (
	"testing"
	"time"

	"sigilum.local/gateway/config"
)

func TestFixedWindowRateLimiterBlocksAfterLimitAndResets(t *testing.T) {
	limiter := newFixedWindowRateLimiter(2, time.Minute)
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)
	key := "demo|alice"

	if !limiter.allow(key, now) {
		t.Fatal("expected first request to pass")
	}
	if !limiter.allow(key, now.Add(5*time.Second)) {
		t.Fatal("expected second request to pass")
	}
	if limiter.allow(key, now.Add(10*time.Second)) {
		t.Fatal("expected third request in same window to be rate-limited")
	}
	if !limiter.allow(key, now.Add(65*time.Second)) {
		t.Fatal("expected limiter window reset to allow request")
	}
}

func TestFixedWindowRateLimiterDisabledWhenLimitZero(t *testing.T) {
	limiter := newFixedWindowRateLimiter(0, time.Minute)
	key := "demo|alice"
	now := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if !limiter.allow(key, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("expected unlimited mode to always allow request %d", i+1)
		}
	}
}

func TestRateLimitKeyNormalizesEmptyValues(t *testing.T) {
	if got := rateLimitKey(" Demo-Conn ", " "); got != "demo-conn|_" {
		t.Fatalf("expected normalized key demo-conn|_, got %q", got)
	}
}

func TestConfigureGatewayRateLimitersAppliesLimits(t *testing.T) {
	configureGatewayRateLimiters(config.Config{
		ClaimRegistrationRateLimit: 1,
		MCPToolCallRateLimit:       1,
	})
	t.Cleanup(func() {
		configureGatewayRateLimiters(config.Config{
			ClaimRegistrationRateLimit: 0,
			MCPToolCallRateLimit:       0,
		})
	})

	if !allowClaimRegistration("demo", "alice") {
		t.Fatal("expected first claim registration attempt to pass")
	}
	if allowClaimRegistration("demo", "alice") {
		t.Fatal("expected second claim registration attempt to be rate-limited")
	}
	if !allowMCPToolCall("demo", "alice") {
		t.Fatal("expected first mcp tool call to pass")
	}
	if allowMCPToolCall("demo", "alice") {
		t.Fatal("expected second mcp tool call to be rate-limited")
	}
}

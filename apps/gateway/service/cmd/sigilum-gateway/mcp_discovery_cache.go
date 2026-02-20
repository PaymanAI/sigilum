package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

type mcpDiscoveryClient interface {
	Discover(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error)
}

type mcpDiscoverySource string

const (
	mcpDiscoverySourceCacheHit     mcpDiscoverySource = "cache_hit"
	mcpDiscoverySourceRefreshed    mcpDiscoverySource = "refreshed"
	mcpDiscoverySourceStaleIfError mcpDiscoverySource = "stale_if_error"
)

type mcpDiscoveryRefreshMode string

const (
	mcpDiscoveryRefreshModeAuto  mcpDiscoveryRefreshMode = "auto"
	mcpDiscoveryRefreshModeForce mcpDiscoveryRefreshMode = "force"
)

type mcpDiscoveryResolution struct {
	Connection       connectors.Connection
	Source           mcpDiscoverySource
	AttemptedRefresh bool
	RefreshError     error
}

func parseMCPDiscoveryRefreshMode(raw string, defaultMode mcpDiscoveryRefreshMode) (mcpDiscoveryRefreshMode, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if defaultMode != mcpDiscoveryRefreshModeAuto && defaultMode != mcpDiscoveryRefreshModeForce {
		defaultMode = mcpDiscoveryRefreshModeAuto
	}
	if normalized == "" {
		return defaultMode, nil
	}
	switch normalized {
	case "auto", "if_stale", "cache", "false", "0", "no":
		return mcpDiscoveryRefreshModeAuto, nil
	case "force", "always", "true", "1", "yes":
		return mcpDiscoveryRefreshModeForce, nil
	default:
		return "", fmt.Errorf("invalid refresh mode %q: expected auto|force", strings.TrimSpace(raw))
	}
}

func resolveMCPDiscovery(
	ctx context.Context,
	connectionID string,
	proxyCfg connectors.ProxyConfig,
	connectorService *connectors.Service,
	discoveryClient mcpDiscoveryClient,
	cacheTTL time.Duration,
	staleIfError time.Duration,
	refreshMode mcpDiscoveryRefreshMode,
	now time.Time,
) (mcpDiscoveryResolution, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		return mcpDiscoveryResolution{}, errors.New("connection id is required")
	}
	if connectorService == nil {
		return mcpDiscoveryResolution{}, errors.New("connector service is required")
	}
	if discoveryClient == nil {
		return mcpDiscoveryResolution{}, errors.New("mcp discovery client is required")
	}
	if refreshMode != mcpDiscoveryRefreshModeAuto && refreshMode != mcpDiscoveryRefreshModeForce {
		return mcpDiscoveryResolution{}, fmt.Errorf("invalid mcp discovery refresh mode %q", refreshMode)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	cached := proxyCfg.Connection.MCPDiscovery
	if refreshMode == mcpDiscoveryRefreshModeAuto && isMCPDiscoveryFresh(cached, cacheTTL, now) {
		return mcpDiscoveryResolution{
			Connection: proxyCfg.Connection,
			Source:     mcpDiscoverySourceCacheHit,
		}, nil
	}

	refreshed, refreshErr := discoveryClient.Discover(ctx, proxyCfg)
	if refreshErr == nil {
		updated, err := connectorService.SaveMCPDiscovery(connectionID, refreshed)
		if err != nil {
			return mcpDiscoveryResolution{}, err
		}
		return mcpDiscoveryResolution{
			Connection:       updated,
			Source:           mcpDiscoverySourceRefreshed,
			AttemptedRefresh: true,
		}, nil
	}

	staleEligible := refreshMode == mcpDiscoveryRefreshModeAuto && canUseMCPDiscoveryStaleIfError(cached, cacheTTL, staleIfError, now)
	persistedConn := proxyCfg.Connection
	failureSnapshot := cached
	if failureSnapshot.LastDiscoveredAt.IsZero() {
		failureSnapshot.LastDiscoveredAt = now
	}
	failureSnapshot.LastDiscoveryError = refreshErr.Error()

	updated, saveErr := connectorService.SaveMCPDiscovery(connectionID, failureSnapshot)
	if saveErr != nil {
		log.Printf("warning: failed to persist mcp discovery error for %s: %v", connectionID, saveErr)
		persistedConn.MCPDiscovery = failureSnapshot
	} else {
		persistedConn = updated
	}

	if staleEligible {
		return mcpDiscoveryResolution{
			Connection:       persistedConn,
			Source:           mcpDiscoverySourceStaleIfError,
			AttemptedRefresh: true,
			RefreshError:     refreshErr,
		}, nil
	}
	return mcpDiscoveryResolution{}, refreshErr
}

func isMCPDiscoveryFresh(discovery connectors.MCPDiscovery, cacheTTL time.Duration, now time.Time) bool {
	if cacheTTL <= 0 {
		return false
	}
	if discovery.LastDiscoveredAt.IsZero() || len(discovery.Tools) == 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	age := now.UTC().Sub(discovery.LastDiscoveredAt.UTC())
	if age < 0 {
		age = 0
	}
	return age <= cacheTTL
}

func canUseMCPDiscoveryStaleIfError(discovery connectors.MCPDiscovery, cacheTTL time.Duration, staleIfError time.Duration, now time.Time) bool {
	if staleIfError <= 0 {
		return false
	}
	if discovery.LastDiscoveredAt.IsZero() || len(discovery.Tools) == 0 {
		return false
	}
	if cacheTTL < 0 {
		cacheTTL = 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	age := now.UTC().Sub(discovery.LastDiscoveredAt.UTC())
	if age < 0 {
		age = 0
	}
	return age <= cacheTTL+staleIfError
}

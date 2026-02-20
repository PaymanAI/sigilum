package main

import (
	"context"
	"log"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
)

const defaultMCPPrewarmTimeout = 20 * time.Second

func maybePrewarmMCPDiscovery(
	connectionID string,
	conn connectors.Connection,
	connectorService *connectors.Service,
	mcpClient *mcpruntime.Client,
) {
	if connectorService == nil || mcpClient == nil {
		return
	}
	if !connectors.IsMCPConnection(conn) || !shouldAutoDiscoverMCPTools(conn) {
		return
	}

	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" {
		connectionID = strings.TrimSpace(conn.ID)
	}
	if connectionID == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultMCPPrewarmTimeout)
		defer cancel()

		proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
		if err != nil {
			log.Printf("mcp prewarm skipped connection=%s reason=%v", connectionID, err)
			return
		}

		discoverStart := time.Now()
		discovery, err := mcpClient.Discover(ctx, proxyCfg)
		if err != nil {
			gatewayMetricRegistry.recordMCPDiscovery("error")
			gatewayMetricRegistry.observeUpstream("mcp", "error", time.Since(discoverStart))
			gatewayMetricRegistry.recordUpstreamError("MCP_DISCOVERY_FAILED")
			log.Printf("mcp prewarm failed connection=%s err=%v", connectionID, err)
			return
		}
		gatewayMetricRegistry.recordMCPDiscovery("success")
		gatewayMetricRegistry.observeUpstream("mcp", "success", time.Since(discoverStart))

		if _, err := connectorService.SaveMCPDiscovery(connectionID, discovery); err != nil {
			log.Printf("mcp prewarm persist failed connection=%s err=%v", connectionID, err)
			return
		}

		log.Printf("mcp prewarm complete connection=%s tools=%d", connectionID, len(discovery.Tools))
	}()
}

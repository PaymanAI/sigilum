package main

import (
	"net/url"
	"strings"
)

func resolveProxyRoute(requestPath string) (connectionID string, upstreamPath string, ok bool) {
	if strings.HasPrefix(requestPath, "/proxy/") {
		rest := strings.TrimPrefix(requestPath, "/proxy/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			return "", "", false
		}
		connectionID = parts[0]
		upstreamPath = "/"
		if len(parts) == 2 && parts[1] != "" {
			upstreamPath = "/" + parts[1]
		}
		return connectionID, upstreamPath, true
	}

	if requestPath == "/slack" || strings.HasPrefix(requestPath, "/slack/") {
		connectionID = slackAliasConnectionID
		upstreamPath = strings.TrimPrefix(requestPath, "/slack")
		if upstreamPath == "" {
			upstreamPath = "/"
		}
		if !strings.HasPrefix(upstreamPath, "/") {
			upstreamPath = "/" + upstreamPath
		}
		return connectionID, upstreamPath, true
	}

	return "", "", false
}

func resolveMCPRoute(requestPath string) (connectionID string, action string, toolName string, ok bool) {
	if !strings.HasPrefix(requestPath, "/mcp/") {
		return "", "", "", false
	}
	rest := strings.Trim(strings.TrimPrefix(requestPath, "/mcp/"), "/")
	if rest == "" {
		return "", "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "tools" {
		return "", "", "", false
	}
	connectionID = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		return connectionID, "list", "", true
	}
	if len(parts) == 4 && parts[3] == "call" {
		decoded, err := url.PathUnescape(parts[2])
		if err != nil {
			return "", "", "", false
		}
		toolName = strings.TrimSpace(decoded)
		if toolName == "" {
			return "", "", "", false
		}
		return connectionID, "call", toolName, true
	}
	return "", "", "", false
}

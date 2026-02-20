package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sigilum.local/gateway/config"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
	"sigilum.local/gateway/internal/util"
)

func handleProxyRequest(
	w http.ResponseWriter,
	r *http.Request,
	nonceCache *nonceReplayCache,
	claimsCache *claimcache.Cache,
	connectorService *connectors.Service,
	cfg config.Config,
) {
	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	connectionID, upstreamPath, ok := resolveProxyRoute(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "invalid proxy path, expected /proxy/{connection_id}/... or /slack/...",
		})
		return
	}
	start := time.Now()
	remoteIP := clientIP(r, cfg.TrustedProxyCIDRs)
	requestID := requestIDFromContext(r.Context())
	logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_request_start", map[string]any{
		"request_id":     requestID,
		"method":         r.Method,
		"connection":     connectionID,
		"path":           upstreamPath,
		"query_present":  strings.TrimSpace(r.URL.RawQuery) != "",
		"remote_ip":      remoteIP,
		"signed_headers": hasSigilumHeaders(r.Header),
	})

	body, err := readLimitedRequestBody(r, cfg.MaxRequestBodyBytes)
	if err != nil {
		writeRequestBodyError(w, err)
		return
	}
	_ = r.Body.Close()

	if _, ok := authorizeConnectionRequest(w, r, body, connectionID, remoteIP, nonceCache, claimsCache, cfg); !ok {
		return
	}

	proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
	if err != nil {
		writeConnectionError(w, err)
		return
	}
	if connectors.IsMCPConnection(proxyCfg.Connection) {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "connection protocol is mcp; use /mcp/{connection_id}/...",
		})
		return
	}
	if block, warning := evaluateRotationPolicy(proxyCfg.Connection, cfg.RotationEnforcement, cfg.RotationGracePeriod, time.Now().UTC()); block {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: warning,
			Code:  "ROTATION_REQUIRED",
		})
		return
	} else if warning != "" {
		w.Header().Set("X-Sigilum-Rotation-Warning", warning)
		logGatewayDecisionIf(cfg.LogProxyRequests, "rotation_warning", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"reason_code": "ROTATION_WARNING",
		})
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.RequestURI = ""

	proxy, err := connectors.NewReverseProxy(proxyCfg, upstreamPath, r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid target config: %v", err)})
		return
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		writeJSON(rw, http.StatusBadGateway, errorResponse{
			Error: "upstream request failed",
			Code:  "UPSTREAM_ERROR",
		})
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_upstream_error", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"decision":    "error",
			"reason_code": "UPSTREAM_ERROR",
			"error":       proxyErr,
		})
	}

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(recorder, r)
	logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_request_end", map[string]any{
		"request_id":     requestID,
		"method":         r.Method,
		"connection":     connectionID,
		"status":         recorder.status,
		"duration_ms":    time.Since(start).Milliseconds(),
		"response_bytes": recorder.bytesWritten,
	})
}

func handleMCPRequest(
	w http.ResponseWriter,
	r *http.Request,
	nonceCache *nonceReplayCache,
	claimsCache *claimcache.Cache,
	connectorService *connectors.Service,
	mcpClient *mcpruntime.Client,
	cfg config.Config,
) {
	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	connectionID, action, toolName, ok := resolveMCPRoute(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "invalid mcp path, expected /mcp/{connection_id}/tools or /mcp/{connection_id}/tools/{tool}/call",
		})
		return
	}

	start := time.Now()
	remoteIP := clientIP(r, cfg.TrustedProxyCIDRs)
	requestID := requestIDFromContext(r.Context())
	logGatewayDecisionIf(cfg.LogProxyRequests, "mcp_request_start", map[string]any{
		"request_id":     requestID,
		"method":         r.Method,
		"connection":     connectionID,
		"action":         action,
		"tool":           toolName,
		"query_present":  strings.TrimSpace(r.URL.RawQuery) != "",
		"remote_ip":      remoteIP,
		"signed_headers": hasSigilumHeaders(r.Header),
	})

	body, err := readLimitedRequestBody(r, cfg.MaxRequestBodyBytes)
	if err != nil {
		writeRequestBodyError(w, err)
		return
	}
	_ = r.Body.Close()

	identity, ok := authorizeConnectionRequest(w, r, body, connectionID, remoteIP, nonceCache, claimsCache, cfg)
	if !ok {
		return
	}

	proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
	if err != nil {
		writeConnectionError(w, err)
		return
	}
	if !connectors.IsMCPConnection(proxyCfg.Connection) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "connection protocol is not mcp"})
		return
	}
	if block, warning := evaluateRotationPolicy(proxyCfg.Connection, cfg.RotationEnforcement, cfg.RotationGracePeriod, time.Now().UTC()); block {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: warning,
			Code:  "ROTATION_REQUIRED",
		})
		return
	} else if warning != "" {
		w.Header().Set("X-Sigilum-Rotation-Warning", warning)
		logGatewayDecisionIf(cfg.LogProxyRequests, "rotation_warning", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"reason_code": "ROTATION_WARNING",
		})
	}

	tools := proxyCfg.Connection.MCPDiscovery.Tools
	if shouldAutoDiscoverMCPTools(proxyCfg.Connection) {
		discovery, err := mcpClient.Discover(r.Context(), proxyCfg)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, errorResponse{
				Error: fmt.Sprintf("mcp discovery failed: %v", err),
				Code:  "MCP_DISCOVERY_FAILED",
			})
			return
		}
		updated, err := connectorService.SaveMCPDiscovery(connectionID, discovery)
		if err != nil {
			writeConnectionError(w, err)
			return
		}
		tools = updated.MCPDiscovery.Tools
		proxyCfg.Connection = updated
	}

	effectivePolicy := mcpruntime.EffectiveToolPolicy(
		proxyCfg.Connection.MCPToolPolicy,
		identity.Subject,
		proxyCfg.Connection.MCPSubjectToolPolicies,
	)

	switch action {
	case "list":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		filteredTools := mcpruntime.FilterTools(tools, effectivePolicy)
		writeJSON(w, http.StatusOK, map[string]any{
			"connection_id": connectionID,
			"subject":       identity.Subject,
			"tools":         filteredTools,
		})
	case "call":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		if !mcpruntime.ToolAllowed(toolName, tools, effectivePolicy) {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Error: fmt.Sprintf("tool %q is not allowed for subject", toolName),
				Code:  "MCP_TOOL_FORBIDDEN",
			})
			return
		}

		arguments, parseErr := resolveToolArguments(body)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: parseErr.Error()})
			return
		}

		result, callErr := mcpClient.CallTool(r.Context(), proxyCfg, toolName, arguments)
		if callErr != nil {
			writeJSON(w, http.StatusBadGateway, errorResponse{
				Error: fmt.Sprintf("mcp tool call failed: %v", callErr),
				Code:  "MCP_TOOL_CALL_FAILED",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"connection_id": connectionID,
			"tool":          toolName,
			"result":        json.RawMessage(result),
		})
	default:
		writeNotFound(w, "mcp action not found")
		return
	}

	logGatewayDecisionIf(cfg.LogProxyRequests, "mcp_request_end", map[string]any{
		"request_id":  requestID,
		"method":      r.Method,
		"connection":  connectionID,
		"action":      action,
		"duration_ms": time.Since(start).Milliseconds(),
	})
}

func resolveToolArguments(body []byte) (json.RawMessage, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return json.RawMessage(`{}`), nil
	}

	var wrapped mcpToolCallRequest
	if err := json.Unmarshal(body, &wrapped); err == nil && len(bytes.TrimSpace(wrapped.Arguments)) > 0 {
		return wrapped.Arguments, nil
	}

	var direct map[string]any
	if err := json.Unmarshal(body, &direct); err != nil {
		return nil, errors.New("request body must be JSON; use {\"arguments\": {...}} or provide the arguments object directly")
	}
	return json.RawMessage(body), nil
}

func runConnectionTest(
	ctx context.Context,
	service *connectors.Service,
	mcpClient *mcpruntime.Client,
	connectionID string,
	input connectors.TestConnectionInput,
) (status string, httpStatus int, testErr string) {
	if ctx == nil {
		ctx = context.Background()
	}
	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		return "fail", 0, err.Error()
	}
	if connectors.IsMCPConnection(proxyCfg.Connection) {
		if _, err := mcpClient.Discover(ctx, proxyCfg); err != nil {
			return "fail", 0, err.Error()
		}
		return "pass", http.StatusOK, ""
	}

	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	testPath := strings.TrimSpace(input.TestPath)
	if testPath == "" {
		testPath = "/"
	}
	if !strings.HasPrefix(testPath, "/") {
		testPath = "/" + testPath
	}
	parsedTestPath, err := url.Parse(testPath)
	if err != nil {
		return "fail", 0, fmt.Sprintf("invalid test_path: %v", err)
	}

	target, err := url.Parse(proxyCfg.Connection.BaseURL)
	if err != nil {
		return "fail", 0, err.Error()
	}
	target.Path = util.JoinPath(target.Path, proxyCfg.Connection.PathPrefix, parsedTestPath.Path)
	target.RawQuery = parsedTestPath.RawQuery

	body := strings.TrimSpace(input.Body)
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, target.String(), bodyReader)
	if err != nil {
		return "fail", 0, err.Error()
	}

	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	connectors.ApplyAuthHeader(req.Header, proxyCfg.Connection, proxyCfg.Secret)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "fail", 0, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "pass", resp.StatusCode, ""
	}
	bodyPreview, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if readErr != nil || len(bodyPreview) == 0 {
		return "fail", resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode)
	}
	message := util.CompactMessage(string(bodyPreview), 240)
	if message == "" {
		return "fail", resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode)
	}
	return "fail", resp.StatusCode, fmt.Sprintf("http %d: %s", resp.StatusCode, message)
}

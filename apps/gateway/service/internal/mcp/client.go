package mcp

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
	"sync"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

const (
	maxResponseBodySize = 2 << 20
	defaultTimeout      = 20 * time.Second
)

type Client struct {
	httpClient *http.Client
	sessionsMu sync.RWMutex
	sessions   map[string]string
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type listToolsResult struct {
	Tools []struct {
		Name           string          `json:"name"`
		Description    string          `json:"description,omitempty"`
		InputSchema    json.RawMessage `json:"inputSchema,omitempty"`
		InputSchemaAlt json.RawMessage `json:"input_schema,omitempty"`
	} `json:"tools"`
}

type initializeResult struct {
	ServerInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	ProtocolVersion    string `json:"protocolVersion,omitempty"`
	ProtocolVersionAlt string `json:"protocol_version,omitempty"`
}

func initializeParams() map[string]any {
	return map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "sigilum-gateway",
			"version": "mvp",
		},
	}
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		sessions:   make(map[string]string),
	}
}

func (c *Client) Discover(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		return connectors.MCPDiscovery{}, err
	}

	initResultRaw, err := c.call(ctx, endpoint, cfg, "initialize", initializeParams())
	if err != nil {
		return connectors.MCPDiscovery{}, err
	}

	var initResult initializeResult
	if err := json.Unmarshal(initResultRaw, &initResult); err != nil {
		return connectors.MCPDiscovery{}, fmt.Errorf("decode initialize result: %w", err)
	}

	tools, err := c.listTools(ctx, endpoint, cfg)
	if err != nil {
		return connectors.MCPDiscovery{}, err
	}

	discovery := connectors.MCPDiscovery{
		Server: connectors.MCPServerInfo{
			Name:            strings.TrimSpace(initResult.ServerInfo.Name),
			Version:         strings.TrimSpace(initResult.ServerInfo.Version),
			ProtocolVersion: strings.TrimSpace(initResult.ProtocolVersion),
		},
		Tools:            tools,
		LastDiscoveredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if discovery.Server.ProtocolVersion == "" {
		discovery.Server.ProtocolVersion = strings.TrimSpace(initResult.ProtocolVersionAlt)
	}
	return discovery, nil
}

func (c *Client) ListTools(ctx context.Context, cfg connectors.ProxyConfig) ([]connectors.MCPTool, error) {
	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		return nil, err
	}
	return c.listTools(ctx, endpoint, cfg)
}

func (c *Client) CallTool(ctx context.Context, cfg connectors.ProxyConfig, name string, arguments json.RawMessage) (json.RawMessage, error) {
	toolName := strings.TrimSpace(name)
	if toolName == "" {
		return nil, errors.New("tool name is required")
	}

	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		return nil, err
	}

	args := map[string]any{}
	if len(bytes.TrimSpace(arguments)) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, errors.New("arguments must be a JSON object")
		}
	}

	return c.call(ctx, endpoint, cfg, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": args,
	})
}

func (c *Client) listTools(ctx context.Context, endpoint string, cfg connectors.ProxyConfig) ([]connectors.MCPTool, error) {
	resultRaw, err := c.call(ctx, endpoint, cfg, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}

	var result listToolsResult
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, fmt.Errorf("decode tools/list result: %w", err)
	}

	tools := make([]connectors.MCPTool, 0, len(result.Tools))
	for _, tool := range result.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		schemaRaw := tool.InputSchema
		if len(schemaRaw) == 0 {
			schemaRaw = tool.InputSchemaAlt
		}
		tools = append(tools, connectors.MCPTool{
			Name:        name,
			Description: strings.TrimSpace(tool.Description),
			InputSchema: compactJSON(schemaRaw),
		})
	}

	return tools, nil
}

func (c *Client) call(ctx context.Context, endpoint string, cfg connectors.ProxyConfig, method string, params any) (json.RawMessage, error) {
	// Per MCP spec, initialize requests must not carry a prior session id.
	if method == "initialize" {
		c.clearSessionID(endpoint)
	}
	// Bootstrap a session opportunistically for non-initialize requests.
	if method != "initialize" && strings.TrimSpace(c.getSessionID(endpoint)) == "" {
		_, _ = c.call(ctx, endpoint, cfg, "initialize", initializeParams())
	}

	requestPayload, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      "sigilum-gateway",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal mcp request: %w", err)
	}

	doRPC := func(forceBearerAuthorization bool) (int, string, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestPayload))
		if err != nil {
			return 0, "", nil, fmt.Errorf("build mcp request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Streamable HTTP MCP servers (e.g. Linear MCP) require clients to accept both
		// JSON responses and SSE streams.
		req.Header.Set("Accept", "application/json, text/event-stream")
		query := req.URL.Query()
		connectors.ApplyAuthQuery(query, cfg.Connection, cfg.Secret)
		req.URL.RawQuery = query.Encode()

		authHeaders := http.Header{}
		if forceBearerAuthorization {
			headerName := strings.TrimSpace(cfg.Connection.AuthHeaderName)
			if headerName == "" {
				headerName = "Authorization"
			}
			secret := strings.TrimSpace(cfg.Secret)
			secret = trimBearerPrefix(secret)
			authHeaders.Set(headerName, "Bearer "+secret)
		} else {
			connectors.ApplyAuthHeader(authHeaders, cfg.Connection, cfg.Secret)
		}
		for key, values := range authHeaders {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		if sessionID := c.getSessionID(endpoint); method != "initialize" && sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return 0, "", nil, fmt.Errorf("mcp request failed: %w", err)
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		if err != nil {
			return 0, "", nil, fmt.Errorf("read mcp response: %w", err)
		}
		if sessionID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); sessionID != "" {
			c.setSessionID(endpoint, sessionID)
		}
		return resp.StatusCode, strings.TrimSpace(resp.Header.Get("Content-Type")), responseBody, nil
	}

	statusCode, contentType, responseBody, err := doRPC(false)
	if err != nil {
		return nil, err
	}

	shouldRetryWithBearer := statusCode == http.StatusUnauthorized &&
		cfg.Connection.Protocol == connectors.ConnectionProtocolMCP &&
		cfg.Connection.AuthMode == connectors.AuthModeHeaderKey &&
		strings.EqualFold(strings.TrimSpace(cfg.Connection.AuthHeaderName), "Authorization") &&
		strings.TrimSpace(cfg.Connection.AuthPrefix) == "" &&
		strings.TrimSpace(cfg.Secret) != "" &&
		!strings.HasPrefix(strings.TrimSpace(cfg.Secret), "Bearer ")

	if shouldRetryWithBearer {
		retryStatusCode, retryContentType, retryResponseBody, retryErr := doRPC(true)
		if retryErr == nil {
			statusCode = retryStatusCode
			contentType = retryContentType
			responseBody = retryResponseBody
		}
	}

	if method != "initialize" && isSessionRequiredResponse(statusCode, responseBody) {
		c.clearSessionID(endpoint)
		if _, initErr := c.call(ctx, endpoint, cfg, "initialize", initializeParams()); initErr == nil {
			retryStatusCode, retryContentType, retryResponseBody, retryErr := doRPC(false)
			if retryErr != nil {
				return nil, retryErr
			}
			statusCode = retryStatusCode
			contentType = retryContentType
			responseBody = retryResponseBody

			shouldRetryWithBearerAfterReinit := statusCode == http.StatusUnauthorized &&
				cfg.Connection.Protocol == connectors.ConnectionProtocolMCP &&
				cfg.Connection.AuthMode == connectors.AuthModeHeaderKey &&
				strings.EqualFold(strings.TrimSpace(cfg.Connection.AuthHeaderName), "Authorization") &&
				strings.TrimSpace(cfg.Connection.AuthPrefix) == "" &&
				strings.TrimSpace(cfg.Secret) != "" &&
				!strings.HasPrefix(strings.TrimSpace(cfg.Secret), "Bearer ")

			if shouldRetryWithBearerAfterReinit {
				retryStatusCode, retryContentType, retryResponseBody, retryErr = doRPC(true)
				if retryErr != nil {
					return nil, retryErr
				}
				statusCode = retryStatusCode
				contentType = retryContentType
				responseBody = retryResponseBody
			}
		}
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("mcp server http %d: %s", statusCode, compactMessage(string(responseBody)))
	}

	rpcPayload, err := extractRPCPayload(contentType, responseBody)
	if err != nil {
		return nil, fmt.Errorf("decode mcp response: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(rpcPayload, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode mcp response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("mcp method %s failed (%d): %s", method, rpcResp.Error.Code, strings.TrimSpace(rpcResp.Error.Message))
	}
	if len(rpcResp.Result) == 0 {
		return nil, fmt.Errorf("mcp method %s returned empty result", method)
	}
	return rpcResp.Result, nil
}

func isSessionRequiredResponse(statusCode int, body []byte) bool {
	if statusCode < 400 || statusCode >= 500 {
		return false
	}
	message := strings.ToLower(compactMessage(string(body)))
	if message == "" {
		return false
	}
	if strings.Contains(message, "mcp-session-id") {
		return true
	}
	sessionNeedles := []string{
		"session required",
		"missing session",
		"invalid session",
		"unknown session",
	}
	for _, needle := range sessionNeedles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func extractRPCPayload(contentType string, body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty response body")
	}

	looksLikeSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream") ||
		bytes.HasPrefix(trimmed, []byte("event:")) ||
		bytes.HasPrefix(trimmed, []byte("data:"))
	if !looksLikeSSE {
		return trimmed, nil
	}

	events := parseSSEDataEvents(string(trimmed))
	if len(events) == 0 {
		return nil, errors.New("stream response missing data payload")
	}
	// Prefer the last JSON-ish payload because MCP servers can emit multiple events.
	for i := len(events) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(events[i])
		if candidate == "" || candidate == "[DONE]" {
			continue
		}
		if strings.HasPrefix(candidate, "{") || strings.HasPrefix(candidate, "[") {
			return []byte(candidate), nil
		}
	}
	return nil, fmt.Errorf("stream response did not contain JSON payload: %s", compactMessage(events[len(events)-1]))
}

func parseSSEDataEvents(payload string) []string {
	lines := strings.Split(payload, "\n")
	events := make([]string, 0, 4)
	currentData := make([]string, 0, 2)

	flush := func() {
		if len(currentData) == 0 {
			return
		}
		events = append(events, strings.Join(currentData, "\n"))
		currentData = currentData[:0]
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			currentData = append(currentData, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()
	return events
}

func resolveEndpoint(conn connectors.Connection) (string, error) {
	if conn.Protocol != connectors.ConnectionProtocolMCP {
		return "", errors.New("connection protocol must be mcp")
	}

	baseURL := strings.TrimSpace(conn.BaseURL)
	if baseURL == "" {
		return "", errors.New("base_url is required")
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base_url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("base_url must include scheme and host")
	}

	endpoint := strings.TrimSpace(conn.MCPEndpoint)
	if endpoint == "" {
		endpoint = "/"
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid mcp endpoint: %w", err)
	}
	if ref.Scheme != "" || ref.Host != "" {
		if ref.Scheme == "" || ref.Host == "" {
			return "", errors.New("mcp endpoint must include scheme and host")
		}
		return ref.String(), nil
	}

	base.Path = joinPath(base.Path, ref.Path)
	base.RawPath = base.Path
	if ref.RawQuery != "" {
		query := base.Query()
		refQuery, err := url.ParseQuery(ref.RawQuery)
		if err != nil {
			return "", fmt.Errorf("invalid mcp endpoint query: %w", err)
		}
		for key, values := range refQuery {
			query.Del(key)
			for _, value := range values {
				query.Add(key, value)
			}
		}
		base.RawQuery = query.Encode()
	}
	return base.String(), nil
}

func joinPath(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		cleaned := strings.Trim(trimmed, "/")
		if cleaned == "" {
			continue
		}
		filtered = append(filtered, cleaned)
	}
	if len(filtered) == 0 {
		return "/"
	}
	return "/" + strings.Join(filtered, "/")
}

func compactJSON(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return ""
	}
	return compact.String()
}

func compactMessage(value string) string {
	compact := strings.Join(strings.Fields(value), " ")
	if compact == "" {
		return ""
	}
	const maxLen = 220
	if len(compact) <= maxLen {
		return compact
	}
	return compact[:maxLen] + "..."
}

func trimBearerPrefix(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "Bearer "))
	}
	if strings.HasPrefix(trimmed, "bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "bearer "))
	}
	return trimmed
}

func (c *Client) getSessionID(endpoint string) string {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	return c.sessions[endpoint]
}

func (c *Client) setSessionID(endpoint string, sessionID string) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	c.sessions[endpoint] = sessionID
}

func (c *Client) clearSessionID(endpoint string) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	delete(c.sessions, endpoint)
}

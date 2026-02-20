package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sigilum.local/gateway/internal/connectors"
	"sigilum.local/gateway/internal/util"
)

const (
	maxResponseBodySize        = 2 << 20
	defaultTimeout             = 20 * time.Second
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 20
	maxSessionRecoveryAttempts = 1
	maxRPCRequestAttempts      = 2
	initialRPCRetryBackoff     = 100 * time.Millisecond
	rpcRetryJitterRatio        = 0.2
)

type sessionState string

const (
	sessionStateUnknown             sessionState = "unknown"
	sessionStateInitializeRequired  sessionState = "initialize_required"
	sessionStateReady               sessionState = "ready"
	sessionStateReinitializePending sessionState = "reinitialize_pending"
)

type Client struct {
	httpClient *http.Client
	sessionsMu sync.RWMutex
	sessions   map[string]string
	requestSeq uint64
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
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &Client{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		sessions: make(map[string]string),
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
		LastDiscoveredAt: time.Now().UTC(),
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
	sessionCacheKey := cacheKeyForConnection(endpoint, cfg)
	if method == "initialize" {
		c.clearSessionID(sessionCacheKey)
	}

	buildRPCPayload := func(rpcMethod string, rpcParams any) ([]byte, error) {
		payload, err := json.Marshal(rpcRequest{
			JSONRPC: "2.0",
			ID:      c.nextRequestID(),
			Method:  rpcMethod,
			Params:  rpcParams,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal mcp request: %w", err)
		}
		return payload, nil
	}

	doRPC := func(rpcMethod string, requestPayload []byte, forceBearerAuthorization bool) (int, string, []byte, error) {
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
		if sessionID := c.getSessionID(sessionCacheKey); rpcMethod != "initialize" && sessionID != "" {
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
			c.setSessionID(sessionCacheKey, sessionID)
		}
		return resp.StatusCode, strings.TrimSpace(resp.Header.Get("Content-Type")), responseBody, nil
	}

	callWithAuthFallback := func(rpcMethod string, requestPayload []byte) (int, string, []byte, error) {
		statusCode, contentType, responseBody, err := doRPC(rpcMethod, requestPayload, false)
		if err != nil {
			return 0, "", nil, err
		}

		if shouldRetryWithBearer(statusCode, cfg) {
			retryStatusCode, retryContentType, retryResponseBody, retryErr := doRPC(rpcMethod, requestPayload, true)
			if retryErr == nil {
				return retryStatusCode, retryContentType, retryResponseBody, nil
			}
		}

		return statusCode, contentType, responseBody, nil
	}

	callWithRetry := func(rpcMethod string, requestPayload []byte) (int, string, []byte, error) {
		backoff := initialRPCRetryBackoff
		lastStatusCode := 0
		lastContentType := ""
		var lastBody []byte
		var lastErr error

		for attempt := 1; attempt <= maxRPCRequestAttempts; attempt++ {
			statusCode, contentType, responseBody, err := callWithAuthFallback(rpcMethod, requestPayload)
			lastStatusCode = statusCode
			lastContentType = contentType
			lastBody = responseBody
			lastErr = err

			shouldRetry, _ := classifyRetryableRPCFailure(statusCode, err)
			if err != nil && !shouldRetry {
				return 0, "", nil, err
			}
			if err == nil && !shouldRetry {
				return statusCode, contentType, responseBody, nil
			}
			if attempt == maxRPCRequestAttempts {
				break
			}
			if !sleepWithContext(ctx, jitterRPCBackoff(backoff)) {
				if cause := context.Cause(ctx); cause != nil {
					return 0, "", nil, cause
				}
				return 0, "", nil, ctx.Err()
			}
			backoff *= 2
		}

		if lastErr != nil {
			return 0, "", nil, lastErr
		}
		return lastStatusCode, lastContentType, lastBody, nil
	}

	validateRPCResult := func(rpcMethod string, contentType string, responseBody []byte) error {
		rpcPayload, err := extractRPCPayload(contentType, responseBody)
		if err != nil {
			return fmt.Errorf("decode mcp response: %w", err)
		}
		var rpcResp rpcResponse
		if err := json.Unmarshal(rpcPayload, &rpcResp); err != nil {
			return fmt.Errorf("decode mcp response: %w", err)
		}
		if rpcResp.Error != nil {
			return fmt.Errorf("mcp method %s failed (%d): %s", rpcMethod, rpcResp.Error.Code, strings.TrimSpace(rpcResp.Error.Message))
		}
		return nil
	}

	decodeRPCResponse := func(rpcMethod string, statusCode int, contentType string, responseBody []byte) (json.RawMessage, error) {
		if statusCode < 200 || statusCode >= 300 {
			return nil, fmt.Errorf("mcp server http %d: %s", statusCode, util.CompactMessage(string(responseBody), 240))
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
			return nil, fmt.Errorf("mcp method %s failed (%d): %s", rpcMethod, rpcResp.Error.Code, strings.TrimSpace(rpcResp.Error.Message))
		}
		if len(rpcResp.Result) == 0 {
			return nil, fmt.Errorf("mcp method %s returned empty result", rpcMethod)
		}
		return rpcResp.Result, nil
	}

	initializeSession := func() error {
		c.clearSessionID(sessionCacheKey)
		initPayload, err := buildRPCPayload("initialize", initializeParams())
		if err != nil {
			return err
		}
		statusCode, contentType, responseBody, err := callWithRetry("initialize", initPayload)
		if err != nil {
			return err
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("mcp server http %d: %s", statusCode, util.CompactMessage(string(responseBody), 240))
		}
		if err := validateRPCResult("initialize", contentType, responseBody); err != nil {
			return err
		}
		return nil
	}

	requestPayload, err := buildRPCPayload(method, params)
	if err != nil {
		return nil, err
	}
	if method == "initialize" {
		statusCode, contentType, responseBody, err := callWithRetry(method, requestPayload)
		if err != nil {
			return nil, err
		}
		return decodeRPCResponse(method, statusCode, contentType, responseBody)
	}

	state := sessionStateUnknown
	if strings.TrimSpace(c.getSessionID(sessionCacheKey)) == "" {
		state = sessionStateInitializeRequired
	} else {
		state = sessionStateReady
	}
	sessionRecoveryAttempts := 0

	for {
		switch state {
		case sessionStateInitializeRequired:
			if err := initializeSession(); err != nil {
				return nil, err
			}
			state = sessionStateReady
			continue
		case sessionStateReady:
			statusCode, contentType, responseBody, err := callWithRetry(method, requestPayload)
			if err != nil {
				return nil, err
			}
			if isSessionRequiredResponse(statusCode, responseBody) {
				if sessionRecoveryAttempts >= maxSessionRecoveryAttempts {
					return nil, fmt.Errorf("mcp method %s requires session reinitialize after %d attempts", method, sessionRecoveryAttempts)
				}
				sessionRecoveryAttempts++
				state = sessionStateReinitializePending
				continue
			}
			return decodeRPCResponse(method, statusCode, contentType, responseBody)
		case sessionStateReinitializePending:
			c.clearSessionID(sessionCacheKey)
			state = sessionStateInitializeRequired
		default:
			return nil, fmt.Errorf("unexpected mcp session state %q", state)
		}
	}
}

func shouldRetryRPCStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func classifyRetryableRPCFailure(statusCode int, err error) (bool, string) {
	if err != nil {
		return classifyRetryableRPCError(err)
	}
	if shouldRetryRPCStatus(statusCode) {
		return true, retryClassForStatus(statusCode)
	}
	if statusCode == 0 {
		return false, "no_status"
	}
	return false, "http_non_retryable"
}

func classifyRetryableRPCError(err error) (bool, string) {
	if err == nil {
		return false, "none"
	}
	if errors.Is(err, context.Canceled) {
		return false, "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true, "context_deadline_exceeded"
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true, "network_timeout"
		}
		if temporaryError(urlErr) {
			return true, "network_temporary"
		}
		return false, "network_non_retryable"
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true, "network_timeout"
		}
		if temporaryError(netErr) {
			return true, "network_temporary"
		}
		return false, "network_non_retryable"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true, "network_operation_error"
	}
	if errors.Is(err, io.EOF) {
		return true, "io_eof"
	}
	return false, "error_non_retryable"
}

func temporaryError(err error) bool {
	type temporary interface {
		Temporary() bool
	}
	t, ok := err.(temporary)
	return ok && t.Temporary()
}

func retryClassForStatus(statusCode int) string {
	switch statusCode {
	case http.StatusTooManyRequests:
		return "http_429"
	case http.StatusBadGateway:
		return "http_502"
	case http.StatusServiceUnavailable:
		return "http_503"
	case http.StatusGatewayTimeout:
		return "http_504"
	default:
		return "http_retryable"
	}
}

func jitterRPCBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	jitterWindow := int64(float64(base) * rpcRetryJitterRatio)
	if jitterWindow <= 0 {
		return base
	}
	delta := rand.Int63n((2 * jitterWindow) + 1)
	adjustment := time.Duration(delta - jitterWindow)
	if base+adjustment <= 0 {
		return base
	}
	return base + adjustment
}

func sleepWithContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	if ctx == nil {
		time.Sleep(duration)
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isSessionRequiredResponse(statusCode int, body []byte) bool {
	if statusCode < 400 || statusCode >= 500 {
		return false
	}
	message := strings.ToLower(util.CompactMessage(string(body), 240))
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
		bytes.HasPrefix(trimmed, []byte("data:")) ||
		bytes.HasPrefix(trimmed, []byte("id:"))
	if !looksLikeSSE {
		return trimmed, nil
	}

	events := parseSSEEvents(string(trimmed))
	if len(events) == 0 {
		return nil, errors.New("stream response missing data payload")
	}
	// Prefer the last JSON-ish payload because MCP servers can emit multiple events.
	for i := len(events) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(strings.Join(events[i].Data, "\n"))
		if candidate == "" || candidate == "[DONE]" {
			continue
		}
		if strings.HasPrefix(candidate, "{") || strings.HasPrefix(candidate, "[") {
			return []byte(candidate), nil
		}
	}
	return nil, fmt.Errorf("stream response did not contain JSON payload: %s", util.CompactMessage(strings.Join(events[len(events)-1].Data, "\n"), 240))
}

type sseEvent struct {
	Event string
	ID    string
	Retry string
	Data  []string
}

func parseSSEEvents(payload string) []sseEvent {
	lines := strings.Split(payload, "\n")
	events := make([]sseEvent, 0, 4)
	current := sseEvent{Data: make([]string, 0, 2)}

	flush := func() {
		if len(current.Data) == 0 && current.Event == "" && current.ID == "" && current.Retry == "" {
			return
		}
		events = append(events, current)
		current = sseEvent{Data: make([]string, 0, 2)}
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
		field := line
		value := ""
		if idx := strings.Index(line, ":"); idx >= 0 {
			field = line[:idx]
			value = strings.TrimPrefix(line[idx+1:], " ")
		}
		switch strings.TrimSpace(field) {
		case "event":
			current.Event = strings.TrimSpace(value)
		case "data":
			current.Data = append(current.Data, value)
		case "id":
			current.ID = strings.TrimSpace(value)
		case "retry":
			current.Retry = strings.TrimSpace(value)
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

	base.Path = util.JoinPath(base.Path, ref.Path)
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

func cacheKeyForConnection(endpoint string, cfg connectors.ProxyConfig) string {
	connectionID := strings.TrimSpace(cfg.Connection.ID)
	if connectionID != "" {
		return "conn:" + connectionID + "\x00" + endpoint
	}

	identityHash := sha256.Sum256([]byte(strings.Join([]string{
		endpoint,
		string(cfg.Connection.Protocol),
		string(cfg.Connection.AuthMode),
		strings.TrimSpace(cfg.Connection.AuthHeaderName),
		cfg.Connection.AuthPrefix,
		strings.TrimSpace(cfg.Secret),
	}, "\x00")))
	return "anon:" + endpoint + "\x00" + hex.EncodeToString(identityHash[:])
}

func shouldRetryWithBearer(statusCode int, cfg connectors.ProxyConfig) bool {
	return statusCode == http.StatusUnauthorized &&
		cfg.Connection.Protocol == connectors.ConnectionProtocolMCP &&
		cfg.Connection.AuthMode == connectors.AuthModeHeaderKey &&
		strings.EqualFold(strings.TrimSpace(cfg.Connection.AuthHeaderName), "Authorization") &&
		strings.TrimSpace(cfg.Connection.AuthPrefix) == "" &&
		strings.TrimSpace(cfg.Secret) != "" &&
		!strings.HasPrefix(strings.TrimSpace(cfg.Secret), "Bearer ")
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

func (c *Client) nextRequestID() string {
	if c == nil {
		return "sigilum-gateway"
	}
	next := atomic.AddUint64(&c.requestSeq, 1)
	return fmt.Sprintf("sigilum-gateway-%d", next)
}

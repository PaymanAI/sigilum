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
	"time"

	"sigilum.local/gateway/internal/connectors"
)

const (
	maxResponseBodySize = 2 << 20
	defaultTimeout      = 20 * time.Second
)

type Client struct {
	httpClient *http.Client
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

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *Client) Discover(ctx context.Context, cfg connectors.ProxyConfig) (connectors.MCPDiscovery, error) {
	endpoint, err := resolveEndpoint(cfg.Connection)
	if err != nil {
		return connectors.MCPDiscovery{}, err
	}

	initResultRaw, err := c.call(ctx, endpoint, cfg, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "sigilum-gateway",
			"version": "mvp",
		},
	})
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
	requestPayload, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      "sigilum-gateway",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal mcp request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestPayload))
	if err != nil {
		return nil, fmt.Errorf("build mcp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	authHeaders := http.Header{}
	connectors.ApplyAuthHeader(authHeaders, cfg.Connection, cfg.Secret)
	for key, values := range authHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read mcp response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mcp server http %d: %s", resp.StatusCode, compactMessage(string(responseBody)))
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(responseBody, &rpcResp); err != nil {
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
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		target, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("invalid mcp endpoint: %w", err)
		}
		if target.Scheme == "" || target.Host == "" {
			return "", errors.New("mcp endpoint must include scheme and host")
		}
		return target.String(), nil
	}

	base.Path = joinPath(base.Path, endpoint)
	base.RawPath = base.Path
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

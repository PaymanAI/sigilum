package connectors

import "time"

type AuthMode string

const (
	AuthModeBearer     AuthMode = "bearer"
	AuthModeHeaderKey  AuthMode = "header_key"
	AuthModeQueryParam AuthMode = "query_param"
)

type ConnectionProtocol string

const (
	ConnectionProtocolHTTP ConnectionProtocol = "http"
	ConnectionProtocolMCP  ConnectionProtocol = "mcp"
)

type MCPTransport string

const (
	MCPTransportStreamableHTTP MCPTransport = "streamable_http"
)

type ConnectionStatus string

const (
	ConnectionStatusActive   ConnectionStatus = "active"
	ConnectionStatusDisabled ConnectionStatus = "disabled"
)

type MCPToolPolicy struct {
	Allowlist       []string `json:"allowlist,omitempty"`
	Denylist        []string `json:"denylist,omitempty"`
	MaxToolsExposed int      `json:"max_tools_exposed,omitempty"`
}

type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema string `json:"input_schema,omitempty"`
}

type MCPServerInfo struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
}

type MCPDiscovery struct {
	Server             MCPServerInfo `json:"server,omitempty"`
	Tools              []MCPTool     `json:"tools,omitempty"`
	LastDiscoveredAt   time.Time     `json:"last_discovered_at,omitempty"`
	LastDiscoveryError string        `json:"last_discovery_error,omitempty"`
}

type Connection struct {
	ID                     string                   `json:"id"`
	Name                   string                   `json:"name"`
	Protocol               ConnectionProtocol       `json:"protocol,omitempty"`
	BaseURL                string                   `json:"base_url"`
	PathPrefix             string                   `json:"path_prefix,omitempty"`
	AuthMode               AuthMode                 `json:"auth_mode"`
	AuthHeaderName         string                   `json:"auth_header_name"`
	AuthPrefix             string                   `json:"auth_prefix"`
	AuthSecretKey          string                   `json:"auth_secret_key,omitempty"`
	CredentialKeys         []string                 `json:"credential_keys,omitempty"`
	MCPTransport           MCPTransport             `json:"mcp_transport,omitempty"`
	MCPEndpoint            string                   `json:"mcp_endpoint,omitempty"`
	MCPToolPolicy          MCPToolPolicy            `json:"mcp_tool_policy,omitempty"`
	MCPSubjectToolPolicies map[string]MCPToolPolicy `json:"mcp_subject_tool_policies,omitempty"`
	MCPDiscovery           MCPDiscovery             `json:"mcp_discovery,omitempty"`
	Status                 ConnectionStatus         `json:"status"`
	CreatedAt              time.Time                `json:"created_at"`
	UpdatedAt              time.Time                `json:"updated_at"`
	LastTestedAt           time.Time                `json:"last_tested_at,omitempty"`
	LastTestStatus         string                   `json:"last_test_status,omitempty"`
	LastTestHTTPStatus     int                      `json:"last_test_http_status,omitempty"`
	LastTestError          string                   `json:"last_test_error,omitempty"`
	LastRotatedAt          time.Time                `json:"last_rotated_at,omitempty"`
	RotationIntervalDays   int                      `json:"rotation_interval_days,omitempty"`
	NextRotationDueAt      time.Time                `json:"next_rotation_due_at,omitempty"`
	SecretVersion          int                      `json:"secret_version"`
}

type CreateConnectionInput struct {
	ID                     string                   `json:"id"`
	Name                   string                   `json:"name"`
	Protocol               string                   `json:"protocol"`
	BaseURL                string                   `json:"base_url"`
	PathPrefix             string                   `json:"path_prefix"`
	AuthMode               string                   `json:"auth_mode"`
	AuthHeaderName         string                   `json:"auth_header_name"`
	AuthPrefix             string                   `json:"auth_prefix"`
	AuthSecretKey          string                   `json:"auth_secret_key"`
	Secrets                map[string]string        `json:"secrets"`
	RotationIntervalDays   int                      `json:"rotation_interval_days"`
	MCPTransport           string                   `json:"mcp_transport"`
	MCPEndpoint            string                   `json:"mcp_endpoint"`
	MCPToolAllowlist       []string                 `json:"mcp_tool_allowlist"`
	MCPToolDenylist        []string                 `json:"mcp_tool_denylist"`
	MCPMaxToolsExposed     int                      `json:"mcp_max_tools_exposed"`
	MCPSubjectToolPolicies map[string]MCPToolPolicy `json:"mcp_subject_tool_policies"`
}

type UpdateConnectionInput struct {
	Name                   string                   `json:"name"`
	PathPrefix             string                   `json:"path_prefix"`
	AuthMode               string                   `json:"auth_mode"`
	AuthHeaderName         string                   `json:"auth_header_name"`
	AuthPrefix             string                   `json:"auth_prefix"`
	AuthSecretKey          string                   `json:"auth_secret_key"`
	RotationIntervalDays   int                      `json:"rotation_interval_days"`
	Status                 string                   `json:"status"`
	MCPEndpoint            string                   `json:"mcp_endpoint"`
	MCPTransport           string                   `json:"mcp_transport"`
	MCPToolAllowlist       []string                 `json:"mcp_tool_allowlist"`
	MCPToolDenylist        []string                 `json:"mcp_tool_denylist"`
	MCPMaxToolsExposed     *int                     `json:"mcp_max_tools_exposed,omitempty"`
	MCPSubjectToolPolicies map[string]MCPToolPolicy `json:"mcp_subject_tool_policies,omitempty"`
}

type RotateSecretInput struct {
	Secrets        map[string]string `json:"secrets"`
	RotatedBy      string            `json:"rotated_by"`
	RotationReason string            `json:"rotation_reason"`
}

type TestConnectionInput struct {
	Method   string            `json:"method"`
	TestPath string            `json:"test_path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body,omitempty"`
}

type ProxyConfig struct {
	Connection Connection
	Secret     string
	Secrets    map[string]string
}

type SharedCredentialVariable struct {
	Key              string    `json:"key"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	CreatedBySubject string    `json:"created_by_subject,omitempty"`
}

type UpsertSharedCredentialVariableInput struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
	CreatedBySubject string `json:"created_by_subject,omitempty"`
}

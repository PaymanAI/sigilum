package catalog

type ServiceCatalog struct {
	Version  string            `json:"version"`
	Services []ServiceTemplate `json:"services"`
}

type ServiceTemplate struct {
	Key                    string                   `json:"key"`
	Label                  string                   `json:"label"`
	Description            string                   `json:"description"`
	ConnectionID           string                   `json:"connection_id"`
	Protocol               string                   `json:"protocol,omitempty"`
	BaseURL                string                   `json:"base_url"`
	MCPBaseURL             string                   `json:"mcp_base_url,omitempty"`
	PathPrefix             string                   `json:"path_prefix"`
	AuthMode               string                   `json:"auth_mode"`
	AuthHeaderName         string                   `json:"auth_header_name"`
	AuthPrefix             string                   `json:"auth_prefix"`
	AuthSecretKey          string                   `json:"auth_secret_key,omitempty"`
	MCPTransport           string                   `json:"mcp_transport,omitempty"`
	MCPEndpoint            string                   `json:"mcp_endpoint,omitempty"`
	MCPToolAllowlist       []string                 `json:"mcp_tool_allowlist,omitempty"`
	MCPToolDenylist        []string                 `json:"mcp_tool_denylist,omitempty"`
	MCPMaxToolsExposed     int                      `json:"mcp_max_tools_exposed,omitempty"`
	MCPSubjectToolPolicies map[string]MCPToolPolicy `json:"mcp_subject_tool_policies,omitempty"`
	DefaultTestPath        string                   `json:"default_test_path"`
	DefaultTestMethod      string                   `json:"default_test_method,omitempty"`
	DefaultTestHeaders     map[string]string        `json:"default_test_headers,omitempty"`
	DefaultTestBody        string                   `json:"default_test_body,omitempty"`
	CredentialFields       []CredentialField        `json:"credential_fields"`
}

type MCPToolPolicy struct {
	Allowlist       []string `json:"allowlist,omitempty"`
	Denylist        []string `json:"denylist,omitempty"`
	MaxToolsExposed int      `json:"max_tools_exposed,omitempty"`
}

type CredentialField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	EnvVar      string `json:"env_var,omitempty"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Help        string `json:"help,omitempty"`
}

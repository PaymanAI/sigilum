package catalog

type ServiceCatalog struct {
	Version  string            `json:"version"`
	Services []ServiceTemplate `json:"services"`
}

type ServiceTemplate struct {
	Key              string            `json:"key"`
	Label            string            `json:"label"`
	Description      string            `json:"description"`
	ConnectionID     string            `json:"connection_id"`
	BaseURL          string            `json:"base_url"`
	PathPrefix       string            `json:"path_prefix"`
	AuthMode         string            `json:"auth_mode"`
	AuthHeaderName   string            `json:"auth_header_name"`
	AuthPrefix       string            `json:"auth_prefix"`
	AuthSecretKey    string            `json:"auth_secret_key,omitempty"`
	DefaultTestPath  string            `json:"default_test_path"`
	DefaultTestMethod string           `json:"default_test_method,omitempty"`
	DefaultTestHeaders map[string]string `json:"default_test_headers,omitempty"`
	DefaultTestBody  string            `json:"default_test_body,omitempty"`
	CredentialFields []CredentialField `json:"credential_fields"`
}

type CredentialField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Help        string `json:"help,omitempty"`
}

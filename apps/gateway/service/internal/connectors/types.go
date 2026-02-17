package connectors

type AuthMode string

const (
	AuthModeBearer   AuthMode = "bearer"
	AuthModeHeaderKey AuthMode = "header_key"
)

type ConnectionStatus string

const (
	ConnectionStatusActive   ConnectionStatus = "active"
	ConnectionStatusDisabled ConnectionStatus = "disabled"
)

type Connection struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	BaseURL             string           `json:"base_url"`
	PathPrefix          string           `json:"path_prefix,omitempty"`
	AuthMode            AuthMode         `json:"auth_mode"`
	AuthHeaderName      string           `json:"auth_header_name"`
	AuthPrefix          string           `json:"auth_prefix"`
	AuthSecretKey       string           `json:"auth_secret_key,omitempty"`
	CredentialKeys      []string         `json:"credential_keys,omitempty"`
	Status              ConnectionStatus `json:"status"`
	CreatedAt           string           `json:"created_at"`
	UpdatedAt           string           `json:"updated_at"`
	LastTestedAt        string           `json:"last_tested_at,omitempty"`
	LastTestStatus      string           `json:"last_test_status,omitempty"`
	LastTestHTTPStatus  int              `json:"last_test_http_status,omitempty"`
	LastTestError       string           `json:"last_test_error,omitempty"`
	LastRotatedAt       string           `json:"last_rotated_at,omitempty"`
	RotationIntervalDays int             `json:"rotation_interval_days,omitempty"`
	NextRotationDueAt   string           `json:"next_rotation_due_at,omitempty"`
	SecretVersion       int              `json:"secret_version"`
}

type CreateConnectionInput struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	BaseURL              string `json:"base_url"`
	PathPrefix           string `json:"path_prefix"`
	AuthMode             string `json:"auth_mode"`
	AuthHeaderName       string `json:"auth_header_name"`
	AuthPrefix           string `json:"auth_prefix"`
	AuthSecretKey        string `json:"auth_secret_key"`
	Secrets              map[string]string `json:"secrets"`
	RotationIntervalDays int    `json:"rotation_interval_days"`
}

type UpdateConnectionInput struct {
	Name                 string `json:"name"`
	PathPrefix           string `json:"path_prefix"`
	AuthSecretKey        string `json:"auth_secret_key"`
	RotationIntervalDays int    `json:"rotation_interval_days"`
	Status               string `json:"status"`
}

type RotateSecretInput struct {
	Secrets        map[string]string `json:"secrets"`
	RotatedBy      string `json:"rotated_by"`
	RotationReason string `json:"rotation_reason"`
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

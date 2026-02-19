package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Store struct {
	filePath string
}

func NewStore(filePath string) *Store {
	return &Store{filePath: filePath}
}

func (s *Store) Load() (ServiceCatalog, error) {
	if strings.TrimSpace(s.filePath) == "" {
		return normalizeCatalog(DefaultCatalog())
	}

	payload, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		defaultCatalog, defaultErr := normalizeCatalog(DefaultCatalog())
		if defaultErr != nil {
			return ServiceCatalog{}, defaultErr
		}
		if saveErr := s.Save(defaultCatalog); saveErr != nil {
			return ServiceCatalog{}, saveErr
		}
		return defaultCatalog, nil
	}
	if err != nil {
		return ServiceCatalog{}, fmt.Errorf("read service catalog: %w", err)
	}

	return parseCatalog(payload)
}

func (s *Store) Save(catalog ServiceCatalog) error {
	normalized, err := normalizeCatalog(catalog)
	if err != nil {
		return err
	}

	if strings.TrimSpace(s.filePath) == "" {
		return errors.New("service catalog file path is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o700); err != nil {
		return fmt.Errorf("create catalog directory: %w", err)
	}

	payload, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode service catalog: %w", err)
	}
	payload = append(payload, '\n')

	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return fmt.Errorf("write temp service catalog: %w", err)
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace service catalog: %w", err)
	}
	return nil
}

func parseCatalog(payload []byte) (ServiceCatalog, error) {
	var catalog ServiceCatalog
	if err := json.Unmarshal(payload, &catalog); err != nil {
		return ServiceCatalog{}, fmt.Errorf("invalid service catalog JSON: %w", err)
	}
	return normalizeCatalog(catalog)
}

func normalizeCatalog(catalog ServiceCatalog) (ServiceCatalog, error) {
	if strings.TrimSpace(catalog.Version) == "" {
		catalog.Version = "v1"
	}

	serviceKeySet := make(map[string]struct{}, len(catalog.Services))
	connectionIDSet := make(map[string]struct{}, len(catalog.Services))
	normalizedServices := make([]ServiceTemplate, 0, len(catalog.Services))

	for index, service := range catalog.Services {
		key := strings.TrimSpace(service.Key)
		if key == "" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].key is required", index)
		}
		if _, exists := serviceKeySet[key]; exists {
			return ServiceCatalog{}, fmt.Errorf("duplicate service key %q", key)
		}
		serviceKeySet[key] = struct{}{}

		connectionID := strings.TrimSpace(service.ConnectionID)
		if connectionID == "" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].connection_id is required", index)
		}
		if _, exists := connectionIDSet[connectionID]; exists {
			return ServiceCatalog{}, fmt.Errorf("duplicate connection_id %q", connectionID)
		}
		connectionIDSet[connectionID] = struct{}{}

		service.Key = key
		service.Label = strings.TrimSpace(service.Label)
		if service.Label == "" {
			service.Label = key
		}
		service.Description = strings.TrimSpace(service.Description)
		service.ConnectionID = connectionID
		service.Protocol = strings.ToLower(strings.TrimSpace(service.Protocol))
		if service.Protocol == "" {
			service.Protocol = "http"
		}
		if service.Protocol != "http" && service.Protocol != "mcp" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].protocol must be http or mcp", index)
		}
		service.BaseURL = strings.TrimSpace(service.BaseURL)
		if service.BaseURL == "" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].base_url is required", index)
		}
		service.MCPBaseURL = strings.TrimSpace(service.MCPBaseURL)
		if service.MCPBaseURL != "" {
			parsedMCPBaseURL, err := url.Parse(service.MCPBaseURL)
			if err != nil || parsedMCPBaseURL.Scheme == "" || parsedMCPBaseURL.Host == "" {
				return ServiceCatalog{}, fmt.Errorf("services[%d].mcp_base_url must be a valid absolute URL", index)
			}
		}
		service.PathPrefix = strings.TrimSpace(service.PathPrefix)
		service.AuthMode = strings.TrimSpace(service.AuthMode)
		if service.AuthMode == "" {
			service.AuthMode = "bearer"
		}
		if service.AuthMode != "bearer" && service.AuthMode != "header_key" && service.AuthMode != "query_param" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].auth_mode must be bearer, header_key, or query_param", index)
		}

		service.AuthHeaderName = strings.TrimSpace(service.AuthHeaderName)
		if service.AuthHeaderName == "" {
			if service.AuthMode == "query_param" {
				service.AuthHeaderName = "api_key"
			} else {
				service.AuthHeaderName = "Authorization"
			}
		}
		service.AuthPrefix = service.AuthPrefix
		if service.AuthMode == "bearer" && service.AuthPrefix == "" {
			service.AuthPrefix = "Bearer "
		}
		if (service.AuthMode == "header_key" || service.AuthMode == "query_param") && service.AuthPrefix == "" {
			service.AuthPrefix = ""
		}

		fieldKeySet := make(map[string]struct{}, len(service.CredentialFields))
		normalizedFields := make([]CredentialField, 0, len(service.CredentialFields))
		for fieldIndex, field := range service.CredentialFields {
			fieldKey := strings.TrimSpace(field.Key)
			if fieldKey == "" {
				return ServiceCatalog{}, fmt.Errorf("services[%d].credential_fields[%d].key is required", index, fieldIndex)
			}
			if _, exists := fieldKeySet[fieldKey]; exists {
				return ServiceCatalog{}, fmt.Errorf("services[%d] duplicate credential field key %q", index, fieldKey)
			}
			fieldKeySet[fieldKey] = struct{}{}

			field.Key = fieldKey
			field.Label = strings.TrimSpace(field.Label)
			if field.Label == "" {
				field.Label = fieldKey
			}
			field.Placeholder = strings.TrimSpace(field.Placeholder)
			field.EnvVar = strings.TrimSpace(field.EnvVar)
			field.Help = strings.TrimSpace(field.Help)
			normalizedFields = append(normalizedFields, field)
		}
		if len(normalizedFields) == 0 && service.Protocol == "http" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].credential_fields must contain at least one field", index)
		}

		service.AuthSecretKey = strings.TrimSpace(service.AuthSecretKey)
		if service.AuthSecretKey == "" && len(normalizedFields) > 0 {
			service.AuthSecretKey = normalizedFields[0].Key
		}
		if service.AuthSecretKey != "" {
			if _, exists := fieldKeySet[service.AuthSecretKey]; !exists {
				return ServiceCatalog{}, fmt.Errorf("services[%d].auth_secret_key %q not found in credential_fields", index, service.AuthSecretKey)
			}
		}
		if service.Protocol == "http" && service.AuthSecretKey == "" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].auth_secret_key is required for http services", index)
		}

		service.MCPTransport = strings.TrimSpace(service.MCPTransport)
		service.MCPEndpoint = strings.TrimSpace(service.MCPEndpoint)
		service.MCPToolAllowlist = normalizeStringList(service.MCPToolAllowlist)
		service.MCPToolDenylist = normalizeStringList(service.MCPToolDenylist)
		if service.MCPMaxToolsExposed < 0 {
			return ServiceCatalog{}, fmt.Errorf("services[%d].mcp_max_tools_exposed must be >= 0", index)
		}
		if service.Protocol == "mcp" {
			if service.MCPBaseURL == "" {
				service.MCPBaseURL = service.BaseURL
			}
			if service.MCPTransport == "" {
				service.MCPTransport = "streamable_http"
			}
			if service.MCPTransport != "streamable_http" {
				return ServiceCatalog{}, fmt.Errorf("services[%d].mcp_transport must be streamable_http", index)
			}
			if service.MCPEndpoint == "" {
				service.MCPEndpoint = "/"
			}
			if !strings.HasPrefix(service.MCPEndpoint, "http://") && !strings.HasPrefix(service.MCPEndpoint, "https://") && !strings.HasPrefix(service.MCPEndpoint, "/") {
				service.MCPEndpoint = "/" + service.MCPEndpoint
			}
		} else {
			// Keep mcp_transport and mcp_endpoint as optional MCP defaults/hints for HTTP templates.
			if service.MCPTransport != "" && service.MCPTransport != "streamable_http" {
				return ServiceCatalog{}, fmt.Errorf("services[%d].mcp_transport must be streamable_http when provided", index)
			}
			if service.MCPEndpoint != "" && !strings.HasPrefix(service.MCPEndpoint, "http://") && !strings.HasPrefix(service.MCPEndpoint, "https://") && !strings.HasPrefix(service.MCPEndpoint, "/") {
				service.MCPEndpoint = "/" + service.MCPEndpoint
			}
			service.MCPToolAllowlist = nil
			service.MCPToolDenylist = nil
			service.MCPMaxToolsExposed = 0
			service.MCPSubjectToolPolicies = nil
		}

		if err := normalizeMCPSubjectPolicies(service.MCPSubjectToolPolicies, index); err != nil {
			return ServiceCatalog{}, err
		}

		if len(normalizedFields) == 0 && service.AuthSecretKey != "" {
			return ServiceCatalog{}, fmt.Errorf("services[%d].auth_secret_key %q not found in credential_fields", index, service.AuthSecretKey)
		}

		service.DefaultTestPath = strings.TrimSpace(service.DefaultTestPath)
		if service.DefaultTestPath == "" {
			service.DefaultTestPath = "/"
		}
		if !strings.HasPrefix(service.DefaultTestPath, "/") {
			service.DefaultTestPath = "/" + service.DefaultTestPath
		}

		service.DefaultTestMethod = strings.ToUpper(strings.TrimSpace(service.DefaultTestMethod))
		if service.DefaultTestMethod == "" {
			service.DefaultTestMethod = "GET"
		}

		normalizedHeaders := make(map[string]string, len(service.DefaultTestHeaders))
		for key, value := range service.DefaultTestHeaders {
			headerKey := strings.TrimSpace(key)
			if headerKey == "" {
				continue
			}
			normalizedHeaders[headerKey] = strings.TrimSpace(value)
		}
		if len(normalizedHeaders) == 0 {
			service.DefaultTestHeaders = nil
		} else {
			service.DefaultTestHeaders = normalizedHeaders
		}
		service.DefaultTestBody = strings.TrimSpace(service.DefaultTestBody)

		service.CredentialFields = normalizedFields
		normalizedServices = append(normalizedServices, service)
	}

	catalog.Services = normalizedServices
	return catalog, nil
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeMCPSubjectPolicies(policies map[string]MCPToolPolicy, serviceIndex int) error {
	for subject, policy := range policies {
		if strings.TrimSpace(subject) == "" {
			return fmt.Errorf("services[%d].mcp_subject_tool_policies contains an empty subject key", serviceIndex)
		}
		if policy.MaxToolsExposed < 0 {
			return fmt.Errorf("services[%d].mcp_subject_tool_policies[%q].max_tools_exposed must be >= 0", serviceIndex, subject)
		}
		policy.Allowlist = normalizeStringList(policy.Allowlist)
		policy.Denylist = normalizeStringList(policy.Denylist)
		policies[subject] = policy
	}
	return nil
}

package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

func normalizeCreateInput(input CreateConnectionInput) (Connection, map[string]string, error) {
	now := time.Now().UTC()
	id := strings.TrimSpace(input.ID)
	if id == "" {
		id = slugify(input.Name)
	}
	if id == "" {
		return Connection{}, nil, errors.New("id or name is required")
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = id
	}

	baseURL := strings.TrimSpace(input.BaseURL)
	if baseURL == "" {
		return Connection{}, nil, errors.New("base_url is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return Connection{}, nil, fmt.Errorf("invalid base_url: %w", err)
	}

	protocol, err := parseConnectionProtocol(input.Protocol)
	if err != nil {
		return Connection{}, nil, err
	}
	mode, err := parseAuthMode(input.AuthMode)
	if err != nil {
		return Connection{}, nil, err
	}

	authHeaderName := strings.TrimSpace(input.AuthHeaderName)
	if authHeaderName == "" {
		switch mode {
		case AuthModeQueryParam:
			authHeaderName = "api_key"
		default:
			authHeaderName = "Authorization"
		}
	}

	authPrefix := input.AuthPrefix
	if input.AuthPrefix == "" {
		switch mode {
		case AuthModeBearer:
			authPrefix = "Bearer "
		case AuthModeHeaderKey, AuthModeQueryParam:
			authPrefix = ""
		}
	}

	secrets, err := normalizeSecretsMap(input.Secrets)
	if err != nil {
		return Connection{}, nil, err
	}

	authSecretKey := strings.TrimSpace(input.AuthSecretKey)
	if authSecretKey != "" {
		if _, ok := secrets[authSecretKey]; !ok {
			return Connection{}, nil, fmt.Errorf("auth_secret_key %q is not present in secrets", authSecretKey)
		}
	}
	if protocol == ConnectionProtocolHTTP {
		if authSecretKey == "" {
			return Connection{}, nil, errors.New("auth_secret_key is required")
		}
		if len(secrets) == 0 {
			return Connection{}, nil, errors.New("secrets are required")
		}
	}

	if protocol != ConnectionProtocolMCP && hasMCPCreateFields(input) {
		return Connection{}, nil, errors.New("mcp fields require protocol=\"mcp\"")
	}

	toolPolicy := MCPToolPolicy{}
	mcpTransport := MCPTransport("")
	mcpEndpoint := ""
	subjectPolicies := map[string]MCPToolPolicy(nil)
	if protocol == ConnectionProtocolMCP {
		transport, err := parseMCPTransport(input.MCPTransport)
		if err != nil {
			return Connection{}, nil, err
		}
		subjectPolicies, err = normalizeSubjectToolPolicies(input.MCPSubjectToolPolicies)
		if err != nil {
			return Connection{}, nil, err
		}
		if input.MCPMaxToolsExposed < 0 {
			return Connection{}, nil, errors.New("mcp_max_tools_exposed must be >= 0")
		}
		mcpTransport = transport
		mcpEndpoint = normalizeMCPEndpoint(input.MCPEndpoint)
		toolPolicy = MCPToolPolicy{
			Allowlist:       normalizeToolNameList(input.MCPToolAllowlist),
			Denylist:        normalizeToolNameList(input.MCPToolDenylist),
			MaxToolsExposed: input.MCPMaxToolsExposed,
		}
	}

	conn := Connection{
		ID:                     id,
		Name:                   name,
		Protocol:               protocol,
		BaseURL:                strings.TrimRight(baseURL, "/"),
		PathPrefix:             normalizePathPrefix(input.PathPrefix),
		AuthMode:               mode,
		AuthHeaderName:         authHeaderName,
		AuthPrefix:             authPrefix,
		AuthSecretKey:          authSecretKey,
		CredentialKeys:         sortedSecretKeys(secrets),
		MCPTransport:           mcpTransport,
		MCPEndpoint:            mcpEndpoint,
		MCPToolPolicy:          toolPolicy,
		MCPSubjectToolPolicies: subjectPolicies,
		Status:                 ConnectionStatusActive,
		CreatedAt:              now,
		UpdatedAt:              now,
		LastRotatedAt:          now,
		SecretVersion:          1,
		RotationIntervalDays:   input.RotationIntervalDays,
	}
	if conn.RotationIntervalDays > 0 {
		conn.NextRotationDueAt = time.Now().UTC().Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour)
	}

	return conn, secrets, nil
}

func metaKey(id string) []byte {
	return []byte(fmt.Sprintf("%s%s/meta", keyConnectionPrefix, id))
}

func secretKey(id string, version int) []byte {
	return []byte(fmt.Sprintf("%s%s/secret/%d", keyConnectionPrefix, id, version))
}

func variableMetaKey(key string) []byte {
	return []byte(fmt.Sprintf("%s%s/meta", keyCredentialVarPrefix, key))
}

func variableSecretKey(key string) []byte {
	return []byte(fmt.Sprintf("%s%s/secret", keyCredentialVarPrefix, key))
}

func normalizePathPrefix(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

func normalizeMCPEndpoint(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "/" {
		return "/"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return strings.TrimRight(trimmed, "/")
	}
	trimmed = "/" + strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func normalizeSecretsMap(secrets map[string]string) (map[string]string, error) {
	normalized := make(map[string]string, len(secrets))
	for key, value := range secrets {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return nil, errors.New("secret key cannot be empty")
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		normalized[trimmedKey] = trimmedValue
	}
	return normalized, nil
}

func mergeSecrets(current map[string]string, secrets map[string]string) (map[string]string, bool, error) {
	next := make(map[string]string, len(current)+len(secrets))
	for key, value := range current {
		next[key] = value
	}

	changed := false
	for key, value := range secrets {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return nil, false, errors.New("secret key cannot be empty")
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		if existing, ok := next[trimmedKey]; !ok || existing != trimmedValue {
			next[trimmedKey] = trimmedValue
			changed = true
		}
	}

	return next, changed, nil
}

func marshalSecretsPayload(values map[string]string) (string, error) {
	payload, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func unmarshalSecretsPayload(payload string) (map[string]string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil, errors.New("secret payload is empty")
	}

	var values map[string]string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, errors.New("invalid secret payload")
	}

	normalized, err := normalizeSecretsMap(values)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func sortedSecretKeys(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sanitizeError(message string) string {
	trimmed := strings.TrimSpace(message)
	if len(trimmed) > 240 {
		return trimmed[:240]
	}
	return trimmed
}

func hasMCPCreateFields(input CreateConnectionInput) bool {
	return strings.TrimSpace(input.MCPTransport) != "" ||
		strings.TrimSpace(input.MCPEndpoint) != "" ||
		len(input.MCPToolAllowlist) > 0 ||
		len(input.MCPToolDenylist) > 0 ||
		input.MCPMaxToolsExposed > 0 ||
		len(input.MCPSubjectToolPolicies) > 0
}

func parseConnectionProtocol(raw string) (ConnectionProtocol, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch ConnectionProtocol(value) {
	case "":
		return ConnectionProtocolHTTP, nil
	case ConnectionProtocolHTTP, ConnectionProtocolMCP:
		return ConnectionProtocol(value), nil
	default:
		return "", fmt.Errorf("invalid protocol: %s", raw)
	}
}

func parseAuthMode(raw string) (AuthMode, error) {
	mode := AuthMode(strings.TrimSpace(raw))
	switch mode {
	case "":
		return AuthModeBearer, nil
	case AuthModeBearer, AuthModeHeaderKey, AuthModeQueryParam:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid auth_mode: %s", raw)
	}
}

func parseMCPTransport(raw string) (MCPTransport, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch MCPTransport(value) {
	case "":
		return MCPTransportStreamableHTTP, nil
	case MCPTransportStreamableHTTP:
		return MCPTransport(value), nil
	default:
		return "", fmt.Errorf("invalid mcp_transport: %s", raw)
	}
}

func normalizeMCPToolPolicy(policy MCPToolPolicy) (MCPToolPolicy, error) {
	if policy.MaxToolsExposed < 0 {
		return MCPToolPolicy{}, errors.New("mcp_max_tools_exposed must be >= 0")
	}
	return MCPToolPolicy{
		Allowlist:       normalizeToolNameList(policy.Allowlist),
		Denylist:        normalizeToolNameList(policy.Denylist),
		MaxToolsExposed: policy.MaxToolsExposed,
	}, nil
}

func normalizeSubjectToolPolicies(policies map[string]MCPToolPolicy) (map[string]MCPToolPolicy, error) {
	if len(policies) == 0 {
		return nil, nil
	}
	normalized := make(map[string]MCPToolPolicy, len(policies))
	for subject, policy := range policies {
		trimmedSubject := strings.TrimSpace(subject)
		if trimmedSubject == "" {
			return nil, errors.New("mcp_subject_tool_policies contains an empty subject key")
		}
		nextPolicy, err := normalizeMCPToolPolicy(policy)
		if err != nil {
			return nil, err
		}
		normalized[trimmedSubject] = nextPolicy
	}
	return normalized, nil
}

func normalizeToolNameList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
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
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeMCPTools(tools []MCPTool) []MCPTool {
	if len(tools) == 0 {
		return nil
	}
	normalized := make([]MCPTool, 0, len(tools))
	seen := map[string]struct{}{}
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, MCPTool{
			Name:        name,
			Description: strings.TrimSpace(tool.Description),
			InputSchema: strings.TrimSpace(tool.InputSchema),
		})
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Name < normalized[j].Name })
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeStoredConnection(conn *Connection) {
	if conn == nil {
		return
	}
	if conn.Protocol == "" {
		conn.Protocol = ConnectionProtocolHTTP
	}
	if conn.AuthMode == "" {
		conn.AuthMode = AuthModeBearer
	}
	if strings.TrimSpace(conn.AuthHeaderName) == "" {
		if conn.AuthMode == AuthModeQueryParam {
			conn.AuthHeaderName = "api_key"
		} else {
			conn.AuthHeaderName = "Authorization"
		}
	}
	if conn.AuthMode == AuthModeBearer && conn.AuthPrefix == "" {
		conn.AuthPrefix = "Bearer "
	}
	if conn.Status == "" {
		conn.Status = ConnectionStatusActive
	}
	if IsMCPConnection(*conn) {
		if conn.MCPTransport == "" {
			conn.MCPTransport = MCPTransportStreamableHTTP
		}
		conn.MCPEndpoint = normalizeMCPEndpoint(conn.MCPEndpoint)
		conn.MCPToolPolicy.Allowlist = normalizeToolNameList(conn.MCPToolPolicy.Allowlist)
		conn.MCPToolPolicy.Denylist = normalizeToolNameList(conn.MCPToolPolicy.Denylist)
		conn.MCPDiscovery.Tools = normalizeMCPTools(conn.MCPDiscovery.Tools)
	}
}

func IsMCPConnection(conn Connection) bool {
	return conn.Protocol == ConnectionProtocolMCP
}

func parseCredentialVariableReference(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, variableRefSuffix) {
		return "", false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "{{"), variableRefSuffix))
	if inner == "" {
		return "", false
	}
	if !isValidCredentialVariableKey(inner) {
		return "", false
	}
	return inner, true
}

func isValidCredentialVariableKey(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 || len(trimmed) > 128 {
		return false
	}
	for _, r := range trimmed {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		isDot := r == '.'
		isHyphen := r == '-'
		isUnderscore := r == '_'
		if !isLower && !isUpper && !isDigit && !isDot && !isHyphen && !isUnderscore {
			return false
		}
	}
	return true
}

func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

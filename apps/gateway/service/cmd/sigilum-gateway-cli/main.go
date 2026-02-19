package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

type kvPairs map[string]string

type stringList []string

func (p *kvPairs) String() string {
	if p == nil || len(*p) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*p))
	for k, v := range *p {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (p *kvPairs) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("expected key=value, got %q", value)
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	if key == "" {
		return errors.New("key cannot be empty")
	}
	if val == "" {
		return errors.New("value cannot be empty")
	}
	if *p == nil {
		*p = map[string]string{}
	}
	(*p)[key] = val
	return nil
}

func (l *stringList) String() string {
	if l == nil || len(*l) == 0 {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		*l = append(*l, trimmed)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	command := os.Args[1]
	args := os.Args[2:]
	var err error
	switch command {
	case "list":
		err = runList(args)
	case "get":
		err = runGet(args)
	case "add":
		err = runAdd(args)
	case "update":
		err = runUpdate(args)
	case "delete":
		err = runDelete(args)
	case "rotate":
		err = runRotate(args)
	case "test":
		err = runTest(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", command)
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, "sigilum-gateway-cli <command> [flags]")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Commands:")
	_, _ = fmt.Fprintln(os.Stderr, "  list                               List configured connections")
	_, _ = fmt.Fprintln(os.Stderr, "  get      --id <id>                 Get one connection")
	_, _ = fmt.Fprintln(os.Stderr, "  add      [flags]                   Create a connection")
	_, _ = fmt.Fprintln(os.Stderr, "  update   --id <id> [flags]         Update connection metadata")
	_, _ = fmt.Fprintln(os.Stderr, "  delete   --id <id>                 Delete a connection")
	_, _ = fmt.Fprintln(os.Stderr, "  rotate   --id <id> --secret k=v    Rotate/add secrets")
	_, _ = fmt.Fprintln(os.Stderr, "  test     --id <id> [flags]         Test upstream connection")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Global environment:")
	_, _ = fmt.Fprintln(os.Stderr, "  GATEWAY_DATA_DIR (default /var/lib/sigilum-gateway)")
	_, _ = fmt.Fprintln(os.Stderr, "  GATEWAY_MASTER_KEY (required)")
}

func parseCommonFlags(fs *flag.FlagSet) (dataDir *string, masterKey *string) {
	defaultDataDir := strings.TrimSpace(os.Getenv("GATEWAY_DATA_DIR"))
	if defaultDataDir == "" {
		defaultDataDir = "/var/lib/sigilum-gateway"
	}
	defaultMasterKey := strings.TrimSpace(os.Getenv("GATEWAY_MASTER_KEY"))
	dataDir = fs.String("data-dir", defaultDataDir, "Gateway data directory")
	masterKey = fs.String("master-key", defaultMasterKey, "Gateway master key")
	return dataDir, masterKey
}

func openService(dataDir string, masterKey string) (*connectors.Service, error) {
	if strings.TrimSpace(masterKey) == "" {
		return nil, errors.New("master key is required (set --master-key or GATEWAY_MASTER_KEY)")
	}
	service, err := connectors.NewService(strings.TrimSpace(dataDir), strings.TrimSpace(masterKey))
	if err != nil {
		return nil, err
	}
	return service, nil
}

func printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(encoded)
	_, _ = os.Stdout.Write([]byte("\n"))
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	connections, err := service.ListConnections()
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"connections": connections})
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	conn, err := service.GetConnection(strings.TrimSpace(*id))
	if err != nil {
		return err
	}
	return printJSON(conn)
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID (optional; derived from name if empty)")
	name := fs.String("name", "", "Connection name")
	protocol := fs.String("protocol", "http", "Connection protocol: http|mcp")
	baseURL := fs.String("base-url", "", "Upstream base URL")
	pathPrefix := fs.String("path-prefix", "", "Upstream path prefix")
	authMode := fs.String("auth-mode", "bearer", "Auth mode: bearer|header_key|query_param")
	authHeaderName := fs.String("auth-header-name", "", "Auth header name")
	authPrefix := fs.String("auth-prefix", "", "Auth value prefix")
	authSecretKey := fs.String("auth-secret-key", "", "Primary secret key name in secrets map")
	rotationDays := fs.Int("rotation-interval-days", 0, "Secret rotation interval in days")
	mcpTransport := fs.String("mcp-transport", "streamable_http", "MCP transport: streamable_http")
	mcpEndpoint := fs.String("mcp-endpoint", "/", "MCP endpoint path or absolute URL")
	mcpMaxTools := fs.Int("mcp-max-tools", 0, "Max MCP tools exposed (0 = unlimited)")
	var mcpAllowlist stringList
	var mcpDenylist stringList
	var secrets kvPairs
	fs.Var(&secrets, "secret", "Connection secret in key=value format (repeatable)")
	fs.Var(&mcpAllowlist, "mcp-allow", "Allowed MCP tool name (repeatable or comma-separated)")
	fs.Var(&mcpDenylist, "mcp-deny", "Denied MCP tool name (repeatable or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*baseURL) == "" {
		return errors.New("--base-url is required")
	}
	isMCP := strings.EqualFold(strings.TrimSpace(*protocol), "mcp")
	if !isMCP {
		if strings.TrimSpace(*authSecretKey) == "" {
			return errors.New("--auth-secret-key is required for http connections")
		}
		if len(secrets) == 0 {
			return errors.New("at least one --secret key=value is required for http connections")
		}
	} else if strings.TrimSpace(*authSecretKey) != "" && len(secrets) == 0 {
		return errors.New("--secret is required when --auth-secret-key is set")
	}

	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	conn, err := service.CreateConnection(connectors.CreateConnectionInput{
		ID:                   strings.TrimSpace(*id),
		Name:                 strings.TrimSpace(*name),
		Protocol:             strings.TrimSpace(*protocol),
		BaseURL:              strings.TrimSpace(*baseURL),
		PathPrefix:           strings.TrimSpace(*pathPrefix),
		AuthMode:             strings.TrimSpace(*authMode),
		AuthHeaderName:       strings.TrimSpace(*authHeaderName),
		AuthPrefix:           *authPrefix,
		AuthSecretKey:        strings.TrimSpace(*authSecretKey),
		Secrets:              secrets,
		RotationIntervalDays: *rotationDays,
		MCPTransport:         strings.TrimSpace(*mcpTransport),
		MCPEndpoint:          strings.TrimSpace(*mcpEndpoint),
		MCPToolAllowlist:     mcpAllowlist,
		MCPToolDenylist:      mcpDenylist,
		MCPMaxToolsExposed:   *mcpMaxTools,
	})
	if err != nil {
		return err
	}
	return printJSON(conn)
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID")
	name := fs.String("name", "", "Connection name")
	pathPrefix := fs.String("path-prefix", "", "Upstream path prefix")
	authMode := fs.String("auth-mode", "", "Auth mode: bearer|header_key|query_param")
	authHeaderName := fs.String("auth-header-name", "", "Auth header or query parameter name")
	authPrefix := fs.String("auth-prefix", "", "Auth value prefix")
	authSecretKey := fs.String("auth-secret-key", "", "Primary secret key name")
	rotationDays := fs.Int("rotation-interval-days", 0, "Secret rotation interval in days")
	status := fs.String("status", "", "Connection status: active|disabled")
	mcpTransport := fs.String("mcp-transport", "", "MCP transport: streamable_http")
	mcpEndpoint := fs.String("mcp-endpoint", "", "MCP endpoint path or absolute URL")
	mcpMaxTools := fs.String("mcp-max-tools", "", "Max MCP tools exposed (0 = unlimited)")
	var mcpAllowlist stringList
	var mcpDenylist stringList
	fs.Var(&mcpAllowlist, "mcp-allow", "Allowed MCP tool name (repeatable or comma-separated)")
	fs.Var(&mcpDenylist, "mcp-deny", "Denied MCP tool name (repeatable or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	var parsedMaxTools *int
	if strings.TrimSpace(*mcpMaxTools) != "" {
		value, err := parseOptionalInt(*mcpMaxTools)
		if err != nil {
			return err
		}
		parsedMaxTools = &value
	}

	conn, err := service.UpdateConnection(strings.TrimSpace(*id), connectors.UpdateConnectionInput{
		Name:                 strings.TrimSpace(*name),
		PathPrefix:           strings.TrimSpace(*pathPrefix),
		AuthMode:             strings.TrimSpace(*authMode),
		AuthHeaderName:       strings.TrimSpace(*authHeaderName),
		AuthPrefix:           *authPrefix,
		AuthSecretKey:        strings.TrimSpace(*authSecretKey),
		RotationIntervalDays: *rotationDays,
		Status:               strings.TrimSpace(*status),
		MCPTransport:         strings.TrimSpace(*mcpTransport),
		MCPEndpoint:          strings.TrimSpace(*mcpEndpoint),
		MCPToolAllowlist:     mcpAllowlist,
		MCPToolDenylist:      mcpDenylist,
		MCPMaxToolsExposed:   parsedMaxTools,
	})
	if err != nil {
		return err
	}
	return printJSON(conn)
}

func parseOptionalInt(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, errors.New("value is required")
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q", raw)
	}
	return parsed, nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	if err := service.DeleteConnection(strings.TrimSpace(*id)); err != nil {
		return err
	}
	return printJSON(map[string]any{"deleted": true, "id": strings.TrimSpace(*id)})
}

func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID")
	rotatedBy := fs.String("rotated-by", "cli", "Rotation actor metadata")
	reason := fs.String("reason", "manual rotation", "Rotation reason metadata")
	var secrets kvPairs
	fs.Var(&secrets, "secret", "New or updated secret in key=value format (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	if len(secrets) == 0 {
		return errors.New("at least one --secret key=value is required")
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	conn, err := service.RotateSecret(strings.TrimSpace(*id), connectors.RotateSecretInput{
		Secrets:        secrets,
		RotatedBy:      strings.TrimSpace(*rotatedBy),
		RotationReason: strings.TrimSpace(*reason),
	})
	if err != nil {
		return err
	}
	return printJSON(conn)
}

func runTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	dataDir, masterKey := parseCommonFlags(fs)
	id := fs.String("id", "", "Connection ID")
	method := fs.String("method", "GET", "HTTP method")
	testPath := fs.String("path", "/", "Request path")
	body := fs.String("body", "", "Request body")
	var headers kvPairs
	fs.Var(&headers, "header", "Request header in key=value format (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id is required")
	}
	service, err := openService(*dataDir, *masterKey)
	if err != nil {
		return err
	}
	defer service.Close()

	status, statusCode, testErr := runConnectionTest(service, strings.TrimSpace(*id), connectors.TestConnectionInput{
		Method:   strings.TrimSpace(*method),
		TestPath: strings.TrimSpace(*testPath),
		Headers:  headers,
		Body:     *body,
	})
	if recordErr := service.RecordTestResult(strings.TrimSpace(*id), status, statusCode, testErr); recordErr != nil {
		return fmt.Errorf("record test result: %w", recordErr)
	}
	return printJSON(map[string]any{
		"status":      status,
		"http_status": statusCode,
		"error":       testErr,
	})
}

func runConnectionTest(service *connectors.Service, connectionID string, input connectors.TestConnectionInput) (status string, httpStatus int, testErr string) {
	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		return "fail", 0, err.Error()
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
	target.Path = joinPath(target.Path, proxyCfg.Connection.PathPrefix, parsedTestPath.Path)
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
	message := compactMessage(string(bodyPreview))
	if message == "" {
		return "fail", resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode)
	}
	return "fail", resp.StatusCode, fmt.Sprintf("http %d: %s", resp.StatusCode, message)
}

func compactMessage(value string) string {
	compact := strings.Join(strings.Fields(value), " ")
	if compact == "" {
		return ""
	}
	const maxLen = 240
	if len(compact) <= maxLen {
		return compact
	}
	return compact[:maxLen] + "..."
}

func joinPath(paths ...string) string {
	parts := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		parts = append(parts, strings.Trim(p, "/"))
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

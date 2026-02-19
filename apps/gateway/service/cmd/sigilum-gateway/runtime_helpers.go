package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
	"sigilum.local/sdk-go/sigilum"
)

var errRequestBodyTooLarge = errors.New("request body exceeds configured limit")

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

func evaluateRotationPolicy(conn connectors.Connection, mode string, gracePeriod time.Duration, now time.Time) (bool, string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "off" {
		return false, ""
	}

	dueAtRaw := strings.TrimSpace(conn.NextRotationDueAt)
	if dueAtRaw == "" {
		return false, ""
	}
	dueAt, err := time.Parse(time.RFC3339Nano, dueAtRaw)
	if err != nil {
		return false, ""
	}

	effectiveDueAt := dueAt.Add(gracePeriod)
	if !now.After(effectiveDueAt) {
		return false, ""
	}

	message := fmt.Sprintf("connection %q secret rotation is overdue (due %s)", conn.ID, dueAt.UTC().Format(time.RFC3339))
	if mode == "block" {
		return true, message
	}
	return false, message
}

func resolveProxyRoute(requestPath string) (connectionID string, upstreamPath string, ok bool) {
	if strings.HasPrefix(requestPath, "/proxy/") {
		rest := strings.TrimPrefix(requestPath, "/proxy/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			return "", "", false
		}
		connectionID = parts[0]
		upstreamPath = "/"
		if len(parts) == 2 && parts[1] != "" {
			upstreamPath = "/" + parts[1]
		}
		return connectionID, upstreamPath, true
	}

	if requestPath == "/slack" || strings.HasPrefix(requestPath, "/slack/") {
		connectionID = slackAliasConnectionID
		upstreamPath = strings.TrimPrefix(requestPath, "/slack")
		if upstreamPath == "" {
			upstreamPath = "/"
		}
		if !strings.HasPrefix(upstreamPath, "/") {
			upstreamPath = "/" + upstreamPath
		}
		return connectionID, upstreamPath, true
	}

	return "", "", false
}

func resolveMCPRoute(requestPath string) (connectionID string, action string, toolName string, ok bool) {
	if !strings.HasPrefix(requestPath, "/mcp/") {
		return "", "", "", false
	}
	rest := strings.Trim(strings.TrimPrefix(requestPath, "/mcp/"), "/")
	if rest == "" {
		return "", "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "tools" {
		return "", "", "", false
	}
	connectionID = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		return connectionID, "list", "", true
	}
	if len(parts) == 4 && parts[3] == "call" {
		decoded, err := url.PathUnescape(parts[2])
		if err != nil {
			return "", "", "", false
		}
		toolName = strings.TrimSpace(decoded)
		if toolName == "" {
			return "", "", "", false
		}
		return connectionID, "call", toolName, true
	}
	return "", "", "", false
}

func resolveServiceAPIKey(connectionID string, defaultValue string, sigilumHomeDir string) string {
	if scoped := strings.TrimSpace(os.Getenv("SIGILUM_SERVICE_API_KEY_" + serviceAPIKeyEnvSuffix(connectionID))); scoped != "" {
		return scoped
	}
	if !isSafeServiceKeyID(connectionID) {
		if fallback := strings.TrimSpace(defaultValue); fallback != "" {
			return fallback
		}
		return ""
	}

	for _, homeDir := range candidateServiceKeyHomes(sigilumHomeDir) {
		raw, err := os.ReadFile(filepath.Join(homeDir, "service-api-key-"+connectionID))
		if err != nil {
			continue
		}
		key := strings.TrimSpace(string(raw))
		if key != "" {
			return key
		}
	}
	if fallback := strings.TrimSpace(defaultValue); fallback != "" {
		return fallback
	}
	return ""
}

func candidateServiceKeyHomes(explicitHome string) []string {
	candidates := []string{}
	if value := strings.TrimSpace(explicitHome); value != "" {
		candidates = append(candidates, value)
	}
	if value := strings.TrimSpace(os.Getenv("SIGILUM_HOME")); value != "" {
		candidates = append(candidates, value)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		candidates = append(candidates, filepath.Join(home, ".sigilum"))
		candidates = append(candidates, filepath.Join(home, ".openclaw", "workspace", ".sigilum"))
		candidates = append(candidates, filepath.Join(home, ".openclaw", ".sigilum"))
	}

	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	return deduped
}

func serviceAPIKeyEnvSuffix(connectionID string) string {
	value := strings.TrimSpace(connectionID)
	if value == "" {
		return "DEFAULT"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 32)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	suffix := strings.Trim(builder.String(), "_")
	if suffix == "" {
		return "DEFAULT"
	}
	return suffix
}

func isSafeServiceKeyID(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 3 || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		ch := v[i]
		isLower := ch >= 'a' && ch <= 'z'
		isDigit := ch >= '0' && ch <= '9'
		isHyphen := ch == '-'
		if !isLower && !isDigit && !isHyphen {
			return false
		}
		if (i == 0 || i == len(v)-1) && !isLower && !isDigit {
			return false
		}
	}
	return true
}

func truncateKeyPrefix(key string, maxLen int) string {
	if key == "" {
		return ""
	}
	if len(key) <= maxLen {
		return key[:len(key)/2] + "..."
	}
	return key[:maxLen] + "..."
}

func writeVerificationFailure(
	w http.ResponseWriter,
	result sigilum.VerifySignatureResult,
	logEnabled bool,
	connectionID string,
	remoteIP string,
) {
	if logEnabled {
		log.Printf("proxy request verify failed connection=%s remote_ip=%s reason=%s", connectionID, remoteIP, result.Reason)
	}
	writeProxyAuthFailure(w)
}

func isMCPConnection(conn connectors.Connection) bool {
	return conn.Protocol == connectors.ConnectionProtocolMCP
}

func extractSigilumIdentity(headers http.Header) (namespace string, publicKey string, subject string, err error) {
	namespace = strings.TrimSpace(headers.Get(headerNamespace))
	if namespace == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerNamespace)
	}
	subject = strings.TrimSpace(headers.Get(headerSubject))
	if subject == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerSubject)
	}
	publicKey = strings.TrimSpace(headers.Get(headerAgentKey))
	if publicKey == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerAgentKey)
	}
	return namespace, publicKey, subject, nil
}

func validateSigilumAuthHeaders(headers http.Header) error {
	for _, header := range []string{
		headerSignatureInput,
		headerSignature,
		headerNamespace,
		headerSubject,
		headerAgentKey,
		headerAgentCert,
	} {
		if len(headers.Values(header)) > 1 {
			return fmt.Errorf("duplicate %s header", header)
		}
	}
	return nil
}

type statusRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(payload)
	r.bytesWritten += n
	return n, err
}

func hasSigilumHeaders(headers http.Header) bool {
	return strings.TrimSpace(headers.Get(headerSignatureInput)) != "" ||
		strings.TrimSpace(headers.Get(headerSignature)) != "" ||
		strings.TrimSpace(headers.Get(headerNamespace)) != "" ||
		strings.TrimSpace(headers.Get(headerSubject)) != "" ||
		strings.TrimSpace(headers.Get(headerAgentKey)) != "" ||
		strings.TrimSpace(headers.Get(headerAgentCert)) != ""
}

func headersToMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[key] = values[0]
	}
	return out
}

func requestAbsoluteURL(r *http.Request, trustedProxyCIDRs []*net.IPNet) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if isTrustedProxy(r.RemoteAddr, trustedProxyCIDRs) {
		if forwarded := firstCSVToken(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			candidate := strings.ToLower(strings.TrimSpace(forwarded))
			if candidate == "http" || candidate == "https" {
				scheme = candidate
			}
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func extractSignatureNonce(signatureInput string) (string, error) {
	needle := `;nonce="`
	index := strings.Index(signatureInput, needle)
	if index < 0 {
		return "", errors.New("invalid signature-input: missing nonce")
	}
	start := index + len(needle)
	end := strings.Index(signatureInput[start:], `"`)
	if end < 0 {
		return "", errors.New("invalid signature-input: malformed nonce")
	}
	nonce := strings.TrimSpace(signatureInput[start : start+end])
	if nonce == "" {
		return "", errors.New("invalid signature-input: empty nonce")
	}
	return nonce, nil
}

func validateSignatureComponents(signatureInput string, hasBody bool) error {
	components, err := parseSignatureComponents(signatureInput)
	if err != nil {
		return err
	}

	expected := []string{"@method", "@target-uri", "sigilum-namespace", "sigilum-subject", "sigilum-agent-key", "sigilum-agent-cert"}
	if hasBody {
		expected = []string{"@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-subject", "sigilum-agent-key", "sigilum-agent-cert"}
	}
	if len(components) != len(expected) {
		return errInvalidSignedComponentSet
	}
	for idx := range expected {
		if components[idx] != expected[idx] {
			return errInvalidSignedComponentSet
		}
	}
	return nil
}

func parseSignatureComponents(signatureInput string) ([]string, error) {
	value := strings.TrimSpace(signatureInput)
	if value == "" {
		return nil, errInvalidSignatureInputFormat
	}
	const prefix = "sig1=("
	const createdMarker = ");created="
	if !strings.HasPrefix(value, prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	end := strings.Index(value, createdMarker)
	if end < 0 || end <= len(prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	raw := strings.TrimSpace(value[len(prefix):end])
	if raw == "" {
		return nil, errInvalidSignatureInputFormat
	}

	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		return nil, errInvalidSignatureInputFormat
	}

	components := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
			return nil, errInvalidSignatureInputFormat
		}
		component := strings.TrimSpace(token[1 : len(token)-1])
		if component == "" {
			return nil, errInvalidSignatureInputFormat
		}
		components = append(components, component)
	}
	return components, nil
}

func isAllowedUnsignedConnection(allow map[string]struct{}, connectionID string) bool {
	if len(allow) == 0 {
		return true
	}
	_, ok := allow[connectionID]
	return ok
}

func joinAllowedConnections(allow map[string]struct{}) string {
	if len(allow) == 0 {
		return "*"
	}
	values := make([]string, 0, len(allow))
	for connectionID := range allow {
		values = append(values, connectionID)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func joinTrustedProxyCIDRs(cidrs []*net.IPNet) string {
	if len(cidrs) == 0 {
		return "(none)"
	}
	values := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr == nil {
			continue
		}
		values = append(values, cidr.String())
	}
	if len(values) == 0 {
		return "(none)"
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func joinAllowedOrigins(allowedOrigins map[string]struct{}) string {
	if len(allowedOrigins) == 0 {
		return "(none)"
	}
	values := make([]string, 0, len(allowedOrigins))
	for origin := range allowedOrigins {
		values = append(values, origin)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func writeConnectionError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, connectors.ErrConnectionNotFound):
		status = http.StatusNotFound
	case errors.Is(err, connectors.ErrConnectionExists):
		status = http.StatusConflict
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func writeCredentialVariableError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, connectors.ErrCredentialVariableNotFound):
		status = http.StatusNotFound
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func readLimitedRequestBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, errors.New("failed to read request body")
	}
	if int64(len(body)) > maxBytes {
		return nil, errRequestBodyTooLarge
	}
	return body, nil
}

func writeRequestBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
			Error: "request body exceeds configured limit",
			Code:  "REQUEST_BODY_TOO_LARGE",
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: "failed to read request body"})
}

func readJSONBody(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return errors.New("failed to read request body")
	}
	if len(body) == 0 {
		return errors.New("request body is required")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
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

func setCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins map[string]struct{}) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Vary", "Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func writeProxyAuthFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error: "request not authorized",
		Code:  "AUTH_FORBIDDEN",
	})
}

func clientIP(r *http.Request, trustedProxyCIDRs []*net.IPNet) string {
	if isTrustedProxy(r.RemoteAddr, trustedProxyCIDRs) {
		if forwarded := firstCSVToken(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return remoteAddrIPString(r.RemoteAddr)
}

func isLoopbackClient(remoteIP string) bool {
	trimmed := strings.TrimSpace(remoteIP)
	if trimmed == "" {
		return false
	}
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isTrustedProxy(remoteAddr string, trustedProxyCIDRs []*net.IPNet) bool {
	if len(trustedProxyCIDRs) == 0 {
		return false
	}
	ip := remoteAddrIP(remoteAddr)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedProxyCIDRs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func firstCSVToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	part := strings.Split(trimmed, ",")[0]
	return strings.TrimSpace(part)
}

func remoteAddrIP(remoteAddr string) net.IP {
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return nil
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

func remoteAddrIPString(remoteAddr string) string {
	ip := remoteAddrIP(remoteAddr)
	if ip != nil {
		return ip.String()
	}
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return "127.0.0.1"
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 && strings.Count(host, ":") == 1 {
		return host[:idx]
	}
	return host
}

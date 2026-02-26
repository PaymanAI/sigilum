package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

type proxyAuthRequiredMarkdownInput struct {
	Namespace         string
	Subject           string
	PublicKey         string
	Service           string
	RemoteIP          string
	ClaimRegistration claimRegistrationAttempt
}

var errRequestBodyTooLarge = errors.New("request body exceeds configured limit")

const (
	codeAuthForbidden              = "AUTH_FORBIDDEN"
	codeAuthHeadersInvalid         = "AUTH_HEADERS_INVALID"
	codeAuthSignatureInvalid       = "AUTH_SIGNATURE_INVALID"
	codeAuthSignedComponents       = "AUTH_SIGNED_COMPONENTS_INVALID"
	codeAuthIdentityInvalid        = "AUTH_IDENTITY_INVALID"
	codeAuthNonceInvalid           = "AUTH_NONCE_INVALID"
	codeAuthReplayDetected         = "AUTH_REPLAY_DETECTED"
	codeAuthClaimsUnavailable      = "AUTH_CLAIMS_UNAVAILABLE"
	codeAuthClaimsLookupFailed     = "AUTH_CLAIMS_LOOKUP_FAILED"
	codeAuthClaimRequired          = "AUTH_CLAIM_REQUIRED"
	codeAuthClaimSubmitRateLimited = "AUTH_CLAIM_SUBMIT_RATE_LIMITED"
	codeMCPToolRateLimited         = "MCP_TOOL_RATE_LIMITED"
)

const defaultGatewayDocsURL = "https://github.com/PaymanAI/sigilum/blob/main/docs/product/GATEWAY_ERROR_CODES.md"

type statusRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

var corsAllowedHeaderSet = map[string]struct{}{
	"authorization":         {},
	"content-digest":        {},
	"content-type":          {},
	"signature":             {},
	"signature-input":       {},
	"sigilum-agent-cert":    {},
	"sigilum-agent-id":      {},
	"sigilum-agent-key":     {},
	"sigilum-namespace":     {},
	"sigilum-subject":       {},
	"x-request-id":          {},
	"x-sigilum-admin-token": {},
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

func readJSONBody(r *http.Request, out any, maxBytes int64) error {
	body, err := readLimitedRequestBody(r, maxBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("request body is required")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSONBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
			Error: "request body exceeds configured limit",
			Code:  "REQUEST_BODY_TOO_LARGE",
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	payload = enrichErrorPayload(w, status, payload)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func enrichErrorPayload(w http.ResponseWriter, status int, payload any) any {
	switch typed := payload.(type) {
	case errorResponse:
		return hydrateErrorResponse(w, status, typed)
	case *errorResponse:
		if typed == nil {
			return payload
		}
		clone := *typed
		return hydrateErrorResponse(w, status, clone)
	default:
		return payload
	}
}

func hydrateErrorResponse(w http.ResponseWriter, status int, payload errorResponse) errorResponse {
	if strings.TrimSpace(payload.RequestID) == "" {
		requestID := strings.TrimSpace(w.Header().Get(requestIDHeader))
		if requestID == "" {
			requestID = newRequestID()
			w.Header().Set(requestIDHeader, requestID)
		}
		payload.RequestID = requestID
	}
	if strings.TrimSpace(payload.Timestamp) == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if strings.TrimSpace(payload.DocsURL) == "" {
		payload.DocsURL = docsURLForError(status, payload.Code)
	}
	return payload
}

func docsURLForError(status int, code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	switch {
	case strings.HasPrefix(normalized, "AUTH_"):
		return defaultGatewayDocsURL + "#auth-errors"
	case strings.HasPrefix(normalized, "ADMIN_"):
		return defaultGatewayDocsURL + "#admin-errors"
	case normalized == "NOT_READY" || status == http.StatusServiceUnavailable:
		return defaultGatewayDocsURL + "#health-and-readiness-errors"
	case strings.HasPrefix(normalized, "MCP_") ||
		normalized == "UPSTREAM_ERROR" ||
		normalized == "ROTATION_REQUIRED" ||
		normalized == "INVALID_REFRESH_MODE":
		return defaultGatewayDocsURL + "#runtime-and-mcp-errors"
	case normalized == "METHOD_NOT_ALLOWED" ||
		normalized == "NOT_FOUND" ||
		normalized == "REQUEST_BODY_TOO_LARGE" ||
		status == http.StatusMethodNotAllowed ||
		status == http.StatusNotFound ||
		status == http.StatusRequestEntityTooLarge:
		return defaultGatewayDocsURL + "#generic-and-operator-errors"
	default:
		return defaultGatewayDocsURL
	}
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, errorResponse{
		Error: "method not allowed",
		Code:  "METHOD_NOT_ALLOWED",
	})
}

func writeNotFound(w http.ResponseWriter, message string) {
	errorMessage := strings.TrimSpace(message)
	if errorMessage == "" {
		errorMessage = "resource not found"
	}
	writeJSON(w, http.StatusNotFound, errorResponse{
		Error: errorMessage,
		Code:  "NOT_FOUND",
	})
}

func setVaryHeaders(existing string, values ...string) string {
	seen := map[string]struct{}{}
	out := []string{}
	if trimmed := strings.TrimSpace(existing); trimmed != "" {
		for _, part := range strings.Split(trimmed, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				continue
			}
			lower := strings.ToLower(value)
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			out = append(out, value)
		}
	}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, trimmed)
	}
	return strings.Join(out, ", ")
}

func resolveAllowedCORSHeaders(requested string) string {
	headers := []string{
		"Content-Type",
		"Authorization",
		"X-Sigilum-Admin-Token",
		"X-Request-Id",
		"Signature-Input",
		"Signature",
		"Content-Digest",
		"Sigilum-Namespace",
		"Sigilum-Subject",
		"Sigilum-Agent-Id",
		"Sigilum-Agent-Key",
		"Sigilum-Agent-Cert",
	}

	seen := map[string]struct{}{}
	for _, header := range headers {
		seen[strings.ToLower(header)] = struct{}{}
	}

	for _, part := range strings.Split(strings.TrimSpace(requested), ",") {
		header := strings.TrimSpace(part)
		if header == "" {
			continue
		}
		lower := strings.ToLower(header)
		if _, ok := corsAllowedHeaderSet[lower]; !ok {
			continue
		}
		if _, ok := seen[lower]; ok {
			continue
		}
		headers = append(headers, header)
		seen[lower] = struct{}{}
	}

	return strings.Join(headers, ", ")
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins map[string]struct{}) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set(
			"Vary",
			setVaryHeaders(
				w.Header().Get("Vary"),
				"Origin",
				"Access-Control-Request-Method",
				"Access-Control-Request-Headers",
			),
		)
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set(
				"Access-Control-Allow-Headers",
				resolveAllowedCORSHeaders(r.Header.Get("Access-Control-Request-Headers")),
			)
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
	}
}

func writeProxyAuthFailure(w http.ResponseWriter) {
	writeProxyAuthError(w, http.StatusForbidden, codeAuthForbidden, "request not authorized")
}

func writeProxyAuthError(w http.ResponseWriter, status int, code string, message string) {
	if status < 400 {
		status = http.StatusForbidden
	}
	errorCode := strings.TrimSpace(code)
	if errorCode == "" {
		errorCode = codeAuthForbidden
	}
	errorMessage := strings.TrimSpace(message)
	if errorMessage == "" {
		errorMessage = "request not authorized"
	}
	if strings.HasPrefix(strings.ToUpper(errorCode), "AUTH_") {
		gatewayMetricRegistry.recordAuthReject(errorCode)
	}
	writeJSON(w, status, errorResponse{
		Error: errorMessage,
		Code:  errorCode,
	})
}

func writeProxyAuthRequiredMarkdown(w http.ResponseWriter, input proxyAuthRequiredMarkdownInput) {
	gatewayMetricRegistry.recordAuthReject(codeAuthClaimRequired)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Sigilum-Code", codeAuthClaimRequired)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(buildProxyAuthRequiredMarkdown(input)))
}

func buildProxyAuthRequiredMarkdown(input proxyAuthRequiredMarkdownInput) string {
	namespace := markdownInline(strings.TrimSpace(input.Namespace))
	if namespace == "" {
		namespace = "(unknown)"
	}
	subject := markdownInline(strings.TrimSpace(input.Subject))
	if subject == "" {
		subject = "(unknown)"
	}
	service := markdownInline(strings.TrimSpace(input.Service))
	if service == "" {
		service = "(unknown)"
	}
	publicKey := markdownInline(truncateForDisplay(strings.TrimSpace(input.PublicKey), 96))
	if publicKey == "" {
		publicKey = "(unknown)"
	}
	remoteIP := markdownInline(strings.TrimSpace(input.RemoteIP))
	if remoteIP == "" {
		remoteIP = "(unknown)"
	}

	var registrationSummary strings.Builder
	registrationSummary.WriteString("- Auto-registration mode: ")
	if input.ClaimRegistration.Enabled {
		registrationSummary.WriteString("`enabled` (gateway)\n")
	} else {
		registrationSummary.WriteString("`disabled`\n")
	}

	if input.ClaimRegistration.Enabled {
		if input.ClaimRegistration.Err != nil {
			registrationSummary.WriteString("- Claim submit result: `failed-before-response`\n")
			registrationSummary.WriteString("- Submit error: `" + markdownInline(truncateForDisplay(input.ClaimRegistration.Err.Error(), 220)) + "`\n")
		} else {
			result := input.ClaimRegistration.Result
			if result.HTTPStatus >= 200 && result.HTTPStatus < 300 {
				registrationSummary.WriteString("- Claim submit result: `recorded`\n")
			} else if result.HTTPStatus > 0 {
				registrationSummary.WriteString("- Claim submit result: `api-rejected`\n")
			} else {
				registrationSummary.WriteString("- Claim submit result: `no-response`\n")
			}
			if result.HTTPStatus > 0 {
				registrationSummary.WriteString(fmt.Sprintf("- Claim API status: `%d`\n", result.HTTPStatus))
			}
			if claimID := markdownInline(strings.TrimSpace(result.ClaimID)); claimID != "" {
				registrationSummary.WriteString("- Claim ID: `" + claimID + "`\n")
			}
			if claimStatus := markdownInline(strings.TrimSpace(result.Status)); claimStatus != "" {
				registrationSummary.WriteString("- Claim state: `" + claimStatus + "`\n")
			}
			if result.Code != "" {
				registrationSummary.WriteString("- Claim API code: `" + markdownInline(result.Code) + "`\n")
			}
			message := strings.TrimSpace(result.Message)
			if message != "" {
				registrationSummary.WriteString("- Claim API message: `" + markdownInline(truncateForDisplay(message, 220)) + "`\n")
			}
		}
	}

	var nextStep string
	if input.ClaimRegistration.Enabled && input.ClaimRegistration.Err == nil {
		code := strings.ToUpper(strings.TrimSpace(input.ClaimRegistration.Result.Code))
		if code == "SIGNATURE_NAMESPACE_MISMATCH" {
			nextStep = fmt.Sprintf(
				"Gateway signer namespace does not match %s. Restart gateway with --namespace %s (or set GATEWAY_SIGILUM_NAMESPACE=%s), then retry.",
				namespace,
				namespace,
				namespace,
			)
		} else {
			status := strings.ToLower(strings.TrimSpace(input.ClaimRegistration.Result.Status))
			switch status {
			case "pending":
				nextStep = "Namespace owner approval is required now. Ask the user to approve/re-approve this agent key for the service, then retry."
			case "approved":
				nextStep = "Access appears approved in the latest claim response. Retry once; if denial continues, ask the user to re-approve and verify namespace/key match."
			case "rejected":
				nextStep = "Request was rejected or revoked by policy/owner action. Ask the user to approve again after policy review."
			default:
				nextStep = "Review claim status in dashboard/API and ask the user to approve/re-approve access if needed."
			}
		}
	} else {
		nextStep = "Review access policy and ask the user to approve/re-approve the claim before retrying."
	}

	return strings.TrimSpace(fmt.Sprintf(`
# HTTP 403 AUTH_CLAIM_REQUIRED: Sigilum Authorization Required

~~~text
+--------------------------------------------------------------------------+
|  /!\  SECURE ACCESS BLOCKED                                              |
|                                                                          |
|  Sigilum verified your signature, but this key is not approved for       |
|  the target service yet. This block protects service credentials and      |
|  prevents unauthorized tool or API execution.                            |
|                                                                          |
|  IMPORTANT: this can happen for first-time access OR when a previous     |
|  approval was revoked/expired. Treat as "authorization required now".    |
+--------------------------------------------------------------------------+
~~~

## Request Context
- Namespace: %s
- Subject: %s
- Service: %s
- Agent key: %s
- Remote IP: %s

## Authorization Registration
%s

## Why this matters
Sigilum is intentionally fail-closed here. Only approved keys can use service credentials.

## Authorization Interpretation
- Gateway returned HTTP 403 AUTH_CLAIM_REQUIRED.
- This means this key currently has **no active approval** for this service.
- Prior approval might have been revoked/expired, so re-approval can be required.

## Agent Instruction
- Do **not** report this as a gateway restart bug.
- Tell the user authorization is required now and ask them to approve/re-approve this agent key.
- After user approval, retry the same request.

## Next Step
%s
`, namespace, subject, service, publicKey, remoteIP, strings.TrimSpace(registrationSummary.String()), markdownInline(nextStep)))
}

func markdownInline(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "`", "'")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func truncateForDisplay(value string, max int) string {
	if max <= 0 {
		return ""
	}
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= max {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:max]) + "..."
}

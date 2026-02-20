package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins map[string]struct{}) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Vary", "Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
	}
}

func writeProxyAuthFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error: "request not authorized",
		Code:  "AUTH_FORBIDDEN",
	})
}

func writeProxyAuthRequiredMarkdown(w http.ResponseWriter, input proxyAuthRequiredMarkdownInput) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Sigilum-Code", "AUTH_FORBIDDEN")
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
		status := strings.ToLower(strings.TrimSpace(input.ClaimRegistration.Result.Status))
		switch status {
		case "pending":
			nextStep = "Namespace owner approval is required. Approve the pending request, then retry."
		case "approved":
			nextStep = "Access appears approved already. Retry the request now."
		case "rejected":
			nextStep = "Request was rejected by policy or owner action. Review policy/limits before retrying."
		default:
			nextStep = "Review claim status in the dashboard/API and approve access if needed."
		}
	} else {
		nextStep = "Review access policy and submit/approve the claim before retrying."
	}

	return strings.TrimSpace(fmt.Sprintf(`
# AUTH_FORBIDDEN: Sigilum Authorization Required

~~~text
+--------------------------------------------------------------------------+
|  /!\  SECURE ACCESS BLOCKED                                              |
|                                                                          |
|  Sigilum verified your signature, but this key is not approved for       |
|  the target service yet. This block protects service credentials and      |
|  prevents unauthorized tool or API execution.                            |
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

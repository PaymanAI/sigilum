package connectors

import (
	"net/http"
	"net/url"
	"strings"
)

func ApplyAuthHeader(headers http.Header, conn Connection, secret string) {
	headerName, headerValue := authHeader(conn, secret)
	if headerName == "" {
		return
	}
	headers.Set(headerName, headerValue)
}

func ApplyAuthQuery(values url.Values, conn Connection, secret string) {
	paramName, paramValue := authQuery(conn, secret)
	if paramName == "" {
		return
	}
	values.Set(paramName, paramValue)
}

func authHeader(conn Connection, secret string) (name string, value string) {
	normalizedSecret := normalizeAuthSecret(conn, secret)

	headerName := strings.TrimSpace(conn.AuthHeaderName)
	if headerName == "" {
		headerName = "Authorization"
	}

	switch conn.AuthMode {
	case AuthModeBearer:
		prefix := conn.AuthPrefix
		if prefix == "" {
			prefix = "Bearer "
		}
		return headerName, prefix + normalizedSecret
	case AuthModeHeaderKey:
		return headerName, conn.AuthPrefix + normalizedSecret
	case AuthModeQueryParam:
		return "", ""
	default:
		prefix := conn.AuthPrefix
		if prefix == "" {
			prefix = "Bearer "
		}
		return headerName, prefix + normalizedSecret
	}
}

func authQuery(conn Connection, secret string) (name string, value string) {
	if conn.AuthMode != AuthModeQueryParam {
		return "", ""
	}

	normalizedSecret := normalizeAuthSecret(conn, secret)
	paramName := strings.TrimSpace(conn.AuthHeaderName)
	if paramName == "" {
		paramName = "api_key"
	}
	return paramName, conn.AuthPrefix + normalizedSecret
}

func normalizeAuthSecret(conn Connection, secret string) string {
	normalizedSecret := strings.TrimSpace(secret)
	normalizedSecret = trimAuthPrefix(normalizedSecret, conn.AuthPrefix)
	normalizedSecret = trimAuthPrefix(normalizedSecret, "Bearer ")
	return normalizedSecret
}

func trimAuthPrefix(secret string, prefix string) string {
	secret = strings.TrimSpace(secret)
	trimmedPrefix := strings.TrimSpace(prefix)
	if trimmedPrefix == "" || len(secret) < len(trimmedPrefix) {
		return secret
	}
	if !strings.EqualFold(secret[:len(trimmedPrefix)], trimmedPrefix) {
		return secret
	}
	if len(secret) == len(trimmedPrefix) {
		return ""
	}

	remainder := secret[len(trimmedPrefix):]
	if remainder == "" {
		return ""
	}
	first := remainder[0]
	if first != ' ' && first != '\t' {
		return secret
	}
	return strings.TrimSpace(remainder)
}

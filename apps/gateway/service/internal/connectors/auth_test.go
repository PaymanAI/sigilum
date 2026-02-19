package connectors

import (
	"net/url"
	"testing"
)

func TestAuthHeaderBearerDefaults(t *testing.T) {
	name, value := authHeader(Connection{AuthMode: AuthModeBearer}, "token-123")
	if name != "Authorization" {
		t.Fatalf("expected Authorization header, got %q", name)
	}
	if value != "Bearer token-123" {
		t.Fatalf("expected Bearer token value, got %q", value)
	}
}

func TestAuthHeaderBearerRespectsConfiguredPrefix(t *testing.T) {
	name, value := authHeader(Connection{
		AuthMode:       AuthModeBearer,
		AuthHeaderName: "Authorization",
		AuthPrefix:     "Bot ",
	}, "bot-token")
	if name != "Authorization" {
		t.Fatalf("expected Authorization header, got %q", name)
	}
	if value != "Bot bot-token" {
		t.Fatalf("expected Bot token value, got %q", value)
	}
}

func TestAuthHeaderBearerDoesNotDoublePrefix(t *testing.T) {
	name, value := authHeader(Connection{
		AuthMode:       AuthModeBearer,
		AuthHeaderName: "Authorization",
		AuthPrefix:     "Bot ",
	}, "Bot bot-token")
	if name != "Authorization" {
		t.Fatalf("expected Authorization header, got %q", name)
	}
	if value != "Bot bot-token" {
		t.Fatalf("expected existing Bot token value, got %q", value)
	}
}

func TestAuthHeaderKeyMode(t *testing.T) {
	name, value := authHeader(Connection{
		AuthMode:       AuthModeHeaderKey,
		AuthHeaderName: "X-API-Key",
		AuthPrefix:     "",
	}, "abc123")
	if name != "X-API-Key" {
		t.Fatalf("expected X-API-Key header, got %q", name)
	}
	if value != "abc123" {
		t.Fatalf("expected raw key value, got %q", value)
	}
}

func TestAuthHeaderBearerOnlyPrefixValue(t *testing.T) {
	_, value := authHeader(Connection{AuthMode: AuthModeBearer}, "Bearer")
	if value != "Bearer " {
		t.Fatalf("expected normalized empty bearer token, got %q", value)
	}
}

func TestAuthHeaderQueryParamModeReturnsEmptyHeader(t *testing.T) {
	name, value := authHeader(Connection{
		AuthMode:       AuthModeQueryParam,
		AuthHeaderName: "TYPEFULLY_API_KEY",
	}, "token-123")
	if name != "" || value != "" {
		t.Fatalf("expected no header for query_param mode, got %q=%q", name, value)
	}
}

func TestApplyAuthQuerySetsConfiguredParam(t *testing.T) {
	values := url.Values{}
	ApplyAuthQuery(values, Connection{
		AuthMode:       AuthModeQueryParam,
		AuthHeaderName: "TYPEFULLY_API_KEY",
	}, "token-123")
	if got := values.Get("TYPEFULLY_API_KEY"); got != "token-123" {
		t.Fatalf("expected query param token-123, got %q", got)
	}
}

func TestApplyAuthQueryStripsBearerPrefix(t *testing.T) {
	values := url.Values{}
	ApplyAuthQuery(values, Connection{
		AuthMode:       AuthModeQueryParam,
		AuthHeaderName: "TYPEFULLY_API_KEY",
	}, "Bearer token-123")
	if got := values.Get("TYPEFULLY_API_KEY"); got != "token-123" {
		t.Fatalf("expected query param token-123, got %q", got)
	}
}

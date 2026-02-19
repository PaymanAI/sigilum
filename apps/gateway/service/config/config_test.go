package config

import "testing"

func TestParseTrustedProxyCIDRs(t *testing.T) {
	cidrs, err := parseTrustedProxyCIDRs("203.0.113.0/24, 10.0.0.1, 2001:db8::/32")
	if err != nil {
		t.Fatalf("expected parse success, got error: %v", err)
	}
	if len(cidrs) != 3 {
		t.Fatalf("expected 3 cidr entries, got %d", len(cidrs))
	}
	if got := cidrs[1].String(); got != "10.0.0.1/32" {
		t.Fatalf("expected single IPv4 to normalize to /32, got %q", got)
	}
}

func TestParseTrustedProxyCIDRsRejectsInvalidEntry(t *testing.T) {
	if _, err := parseTrustedProxyCIDRs("not-a-cidr"); err == nil {
		t.Fatalf("expected parse failure for invalid entry")
	}
}

func TestLoadDefaultsRequireSignedAdminChecks(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_REQUIRE_SIGNED_ADMIN_CHECKS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.RequireSignedAdminChecks {
		t.Fatalf("expected require_signed_admin_checks default to true")
	}
}

func TestLoadAllowsDisablingSignedAdminChecks(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_REQUIRE_SIGNED_ADMIN_CHECKS", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.RequireSignedAdminChecks {
		t.Fatalf("expected require_signed_admin_checks to be false when overridden")
	}
}

func TestLoadParsesMaxRequestBodyBytes(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_MAX_REQUEST_BODY_BYTES", "2097152")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.MaxRequestBodyBytes != 2097152 {
		t.Fatalf("expected max request body bytes to be 2097152, got %d", cfg.MaxRequestBodyBytes)
	}
}

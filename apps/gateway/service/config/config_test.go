package config

import (
	"path/filepath"
	"testing"
	"time"
)

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
	if cfg.AdminAccessMode != AdminAccessModeHybrid {
		t.Fatalf("expected admin access mode default to hybrid, got %q", cfg.AdminAccessMode)
	}
}

func TestLoadDefaultsEnableAutoRegisterClaims(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_AUTO_REGISTER_CLAIMS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.AutoRegisterClaims {
		t.Fatalf("expected auto_register_claims default to true")
	}
}

func TestLoadAllowsDisablingAutoRegisterClaims(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_AUTO_REGISTER_CLAIMS", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.AutoRegisterClaims {
		t.Fatalf("expected auto_register_claims to be false when overridden")
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

func TestLoadRejectsInvalidAdminAccessMode(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_ADMIN_ACCESS_MODE", "invalid-mode")

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid admin access mode to fail config load")
	}
}

func TestLoadRequiresTokenForTokenMode(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_ADMIN_ACCESS_MODE", "token")
	t.Setenv("GATEWAY_ADMIN_TOKEN", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected token mode without token to fail config load")
	}
}

func TestLoadAllowsTokenModeWithToken(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_ADMIN_ACCESS_MODE", "token")
	t.Setenv("GATEWAY_ADMIN_TOKEN", "test-token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config load success, got error: %v", err)
	}
	if cfg.AdminAccessMode != AdminAccessModeToken {
		t.Fatalf("expected token admin access mode, got %q", cfg.AdminAccessMode)
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

func TestLoadDefaultsDataDirToUserHome(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/tmp/sigilum-test-home")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	expected := filepath.Join("/tmp/sigilum-test-home", ".local", "share", "sigilum-gateway")
	if cfg.DataDir != expected {
		t.Fatalf("expected data dir %q, got %q", expected, cfg.DataDir)
	}
}

func TestLoadPrefersXDGDataHome(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "/tmp/sigilum-xdg")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	expected := filepath.Join("/tmp/sigilum-xdg", "sigilum-gateway")
	if cfg.DataDir != expected {
		t.Fatalf("expected data dir %q, got %q", expected, cfg.DataDir)
	}
}

func TestLoadParsesShutdownTimeoutSeconds(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_SHUTDOWN_TIMEOUT_SECONDS", "25")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ShutdownTimeout != 25*time.Second {
		t.Fatalf("expected shutdown timeout 25s, got %s", cfg.ShutdownTimeout)
	}
}

func TestLoadParsesClaimsCacheMaxApproved(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_CLAIMS_CACHE_MAX_APPROVED", "321")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ClaimsCacheMaxApproved != 321 {
		t.Fatalf("expected claims cache max approved 321, got %d", cfg.ClaimsCacheMaxApproved)
	}
}

func TestLoadParsesRouteTimeouts(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_ADMIN_TIMEOUT_SECONDS", "25")
	t.Setenv("GATEWAY_PROXY_TIMEOUT_SECONDS", "180")
	t.Setenv("GATEWAY_MCP_TIMEOUT_SECONDS", "75")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.AdminRequestTimeout != 25*time.Second {
		t.Fatalf("expected admin timeout 25s, got %s", cfg.AdminRequestTimeout)
	}
	if cfg.ProxyRequestTimeout != 180*time.Second {
		t.Fatalf("expected proxy timeout 180s, got %s", cfg.ProxyRequestTimeout)
	}
	if cfg.MCPRequestTimeout != 75*time.Second {
		t.Fatalf("expected mcp timeout 75s, got %s", cfg.MCPRequestTimeout)
	}
}

func TestLoadParsesMCPDiscoveryCachePolicy(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_MCP_DISCOVERY_CACHE_TTL_SECONDS", "120")
	t.Setenv("GATEWAY_MCP_DISCOVERY_STALE_IF_ERROR_SECONDS", "900")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.MCPDiscoveryCacheTTL != 120*time.Second {
		t.Fatalf("expected mcp discovery cache ttl 120s, got %s", cfg.MCPDiscoveryCacheTTL)
	}
	if cfg.MCPDiscoveryStaleIfError != 900*time.Second {
		t.Fatalf("expected mcp discovery stale-if-error window 900s, got %s", cfg.MCPDiscoveryStaleIfError)
	}
}

func TestLoadRejectsNegativeMCPDiscoveryStaleIfError(t *testing.T) {
	t.Setenv("GATEWAY_MASTER_KEY", "test-master-key")
	t.Setenv("GATEWAY_MCP_DISCOVERY_STALE_IF_ERROR_SECONDS", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("expected negative stale-if-error window to fail config load")
	}
}

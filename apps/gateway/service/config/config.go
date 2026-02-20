package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	AdminAccessModeLoopback = "loopback"
	AdminAccessModeToken    = "token"
	AdminAccessModeHybrid   = "hybrid"
)

type Config struct {
	Addr                       string
	DataDir                    string
	MasterKey                  string
	ServiceCatalogFile         string
	RegistryURL                string
	RegistryRequestTimeout     time.Duration
	ClaimsCacheTTL             time.Duration
	ClaimsCacheRefreshInterval time.Duration
	ClaimsCacheMaxApproved     int
	MCPDiscoveryCacheTTL       time.Duration
	MCPDiscoveryStaleIfError   time.Duration
	SigilumNamespace           string
	SigilumHomeDir             string
	ServiceAPIKey              string
	AllowedOrigins             map[string]struct{}
	TrustedProxyCIDRs          []*net.IPNet
	LogProxyRequests           bool
	AutoRegisterClaims         bool
	AllowUnsignedProxy         bool
	AllowUnsignedFor           map[string]struct{}
	RequireSignedAdminChecks   bool
	AdminAccessMode            string
	AdminToken                 string
	MaxRequestBodyBytes        int64
	RotationEnforcement        string
	RotationGracePeriod        time.Duration
	TimestampTolerance         time.Duration
	NonceTTL                   time.Duration
	ShutdownTimeout            time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Addr:               getEnv("GATEWAY_ADDR", ":38100"),
		DataDir:            getEnv("GATEWAY_DATA_DIR", defaultGatewayDataDir()),
		ServiceCatalogFile: getEnv("GATEWAY_SERVICE_CATALOG_FILE", ""),
		MasterKey:          getEnv("GATEWAY_MASTER_KEY", ""),
		RegistryURL:        getEnv("SIGILUM_REGISTRY_URL", getEnv("SIGILUM_API_URL", "https://api.sigilum.id")),
		SigilumNamespace:   getEnv("GATEWAY_SIGILUM_NAMESPACE", getEnv("SIGILUM_NAMESPACE", "")),
		SigilumHomeDir:     getEnv("GATEWAY_SIGILUM_HOME", getEnv("SIGILUM_HOME", "")),
		ServiceAPIKey:      getEnv("SIGILUM_SERVICE_API_KEY", ""),
		AllowedOrigins: parseCSVSet(getEnv(
			"GATEWAY_ALLOWED_ORIGINS",
			"http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:3000,http://localhost:38000,http://127.0.0.1:38000,https://sigilum.id",
		)),
		ClaimsCacheTTL:             30 * time.Second,
		ClaimsCacheRefreshInterval: 10 * time.Second,
		ClaimsCacheMaxApproved:     10_000,
		MCPDiscoveryCacheTTL:       5 * time.Minute,
		MCPDiscoveryStaleIfError:   time.Hour,
		TrustedProxyCIDRs:          []*net.IPNet{},
		LogProxyRequests:           true,
		AutoRegisterClaims:         true,
		AllowUnsignedProxy:         false,
		AllowUnsignedFor:           map[string]struct{}{},
		RequireSignedAdminChecks:   true,
		AdminAccessMode:            AdminAccessModeHybrid,
		AdminToken:                 getEnv("GATEWAY_ADMIN_TOKEN", ""),
		MaxRequestBodyBytes:        2 << 20,
		RotationEnforcement:        "warn",
		RotationGracePeriod:        0,
		TimestampTolerance:         5 * time.Minute,
		NonceTTL:                   10 * time.Minute,
		ShutdownTimeout:            15 * time.Second,
		RegistryRequestTimeout:     60 * time.Second,
	}

	if cfg.MasterKey == "" {
		return Config{}, fmt.Errorf("GATEWAY_MASTER_KEY is required")
	}
	if cfg.ServiceCatalogFile == "" {
		cfg.ServiceCatalogFile = cfg.DataDir + "/service-catalog.json"
	}
	if value, err := getEnvBool("GATEWAY_LOG_PROXY_REQUESTS", cfg.LogProxyRequests); err != nil {
		return Config{}, err
	} else {
		cfg.LogProxyRequests = value
	}
	if value, err := getEnvBool("GATEWAY_AUTO_REGISTER_CLAIMS", cfg.AutoRegisterClaims); err != nil {
		return Config{}, err
	} else {
		cfg.AutoRegisterClaims = value
	}
	if value, err := getEnvBool("GATEWAY_ALLOW_UNSIGNED_PROXY", cfg.AllowUnsignedProxy); err != nil {
		return Config{}, err
	} else {
		cfg.AllowUnsignedProxy = value
	}
	if value, err := getEnvBool("GATEWAY_REQUIRE_SIGNED_ADMIN_CHECKS", cfg.RequireSignedAdminChecks); err != nil {
		return Config{}, err
	} else {
		cfg.RequireSignedAdminChecks = value
	}
	switch value := strings.ToLower(strings.TrimSpace(getEnv("GATEWAY_ADMIN_ACCESS_MODE", cfg.AdminAccessMode))); value {
	case AdminAccessModeLoopback, AdminAccessModeToken, AdminAccessModeHybrid:
		cfg.AdminAccessMode = value
	default:
		return Config{}, fmt.Errorf("invalid GATEWAY_ADMIN_ACCESS_MODE value %q: expected loopback|token|hybrid", value)
	}
	if cfg.RequireSignedAdminChecks && cfg.AdminAccessMode == AdminAccessModeToken && strings.TrimSpace(cfg.AdminToken) == "" {
		return Config{}, fmt.Errorf("GATEWAY_ADMIN_TOKEN is required when GATEWAY_ADMIN_ACCESS_MODE=token")
	}
	if value, err := getEnvInt("GATEWAY_MAX_REQUEST_BODY_BYTES", int(cfg.MaxRequestBodyBytes)); err != nil {
		return Config{}, err
	} else {
		cfg.MaxRequestBodyBytes = int64(value)
	}
	cfg.AllowUnsignedFor = parseCSVSet(getEnv("GATEWAY_ALLOW_UNSIGNED_CONNECTIONS", ""))
	if origins, err := parseAllowedOrigins(getEnv("GATEWAY_ALLOWED_ORIGINS", joinCSVSet(cfg.AllowedOrigins))); err != nil {
		return Config{}, err
	} else {
		cfg.AllowedOrigins = origins
	}

	switch value := strings.ToLower(strings.TrimSpace(getEnv("GATEWAY_ROTATION_ENFORCEMENT", cfg.RotationEnforcement))); value {
	case "off", "warn", "block":
		cfg.RotationEnforcement = value
	default:
		return Config{}, fmt.Errorf("invalid GATEWAY_ROTATION_ENFORCEMENT value %q: expected off|warn|block", value)
	}

	if days, err := getEnvIntMin("GATEWAY_ROTATION_GRACE_DAYS", 0, 0); err != nil {
		return Config{}, err
	} else {
		cfg.RotationGracePeriod = time.Duration(days) * 24 * time.Hour
	}

	if seconds, err := getEnvInt("SIGILUM_TIMESTAMP_TOLERANCE_SECONDS", 300); err != nil {
		return Config{}, err
	} else {
		cfg.TimestampTolerance = time.Duration(seconds) * time.Second
	}

	if seconds, err := getEnvInt("SIGILUM_NONCE_TTL_SECONDS", 600); err != nil {
		return Config{}, err
	} else {
		cfg.NonceTTL = time.Duration(seconds) * time.Second
	}
	if seconds, err := getEnvInt("GATEWAY_SHUTDOWN_TIMEOUT_SECONDS", int(cfg.ShutdownTimeout/time.Second)); err != nil {
		return Config{}, err
	} else {
		cfg.ShutdownTimeout = time.Duration(seconds) * time.Second
	}
	if seconds, err := getEnvInt("GATEWAY_CLAIMS_CACHE_TTL_SECONDS", int(cfg.ClaimsCacheTTL/time.Second)); err != nil {
		return Config{}, err
	} else {
		cfg.ClaimsCacheTTL = time.Duration(seconds) * time.Second
	}
	if seconds, err := getEnvInt("GATEWAY_CLAIMS_CACHE_REFRESH_SECONDS", int(cfg.ClaimsCacheRefreshInterval/time.Second)); err != nil {
		return Config{}, err
	} else {
		cfg.ClaimsCacheRefreshInterval = time.Duration(seconds) * time.Second
	}
	if value, err := getEnvInt("GATEWAY_CLAIMS_CACHE_MAX_APPROVED", cfg.ClaimsCacheMaxApproved); err != nil {
		return Config{}, err
	} else {
		cfg.ClaimsCacheMaxApproved = value
	}
	if seconds, err := getEnvIntMin("GATEWAY_MCP_DISCOVERY_CACHE_TTL_SECONDS", int(cfg.MCPDiscoveryCacheTTL/time.Second), 0); err != nil {
		return Config{}, err
	} else {
		cfg.MCPDiscoveryCacheTTL = time.Duration(seconds) * time.Second
	}
	if seconds, err := getEnvIntMin("GATEWAY_MCP_DISCOVERY_STALE_IF_ERROR_SECONDS", int(cfg.MCPDiscoveryStaleIfError/time.Second), 0); err != nil {
		return Config{}, err
	} else {
		cfg.MCPDiscoveryStaleIfError = time.Duration(seconds) * time.Second
	}
	if cfg.ClaimsCacheRefreshInterval > cfg.ClaimsCacheTTL {
		cfg.ClaimsCacheRefreshInterval = cfg.ClaimsCacheTTL
	}
	if cidrs, err := parseTrustedProxyCIDRs(getEnv("GATEWAY_TRUSTED_PROXY_CIDRS", "")); err != nil {
		return Config{}, err
	} else {
		cfg.TrustedProxyCIDRs = cidrs
	}

	return cfg, nil
}

func defaultGatewayDataDir() string {
	if xdgDataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdgDataHome != "" {
		return xdgDataHome + "/sigilum-gateway"
	}
	if homeDir, err := os.UserHomeDir(); err == nil && strings.TrimSpace(homeDir) != "" {
		return homeDir + "/.local/share/sigilum-gateway"
	}
	return "./gateway-data"
}

func getEnv(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(name string, defaultValue bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s value %q: expected true|false", name, raw)
	}
}

func parseCSVSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out
	}
	for _, part := range strings.Split(trimmed, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func joinCSVSet(values map[string]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	return strings.Join(out, ",")
}

func getEnvInt(name string, defaultValue int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: %w", name, raw, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("invalid %s value %d: must be > 0", name, value)
	}
	return value, nil
}

func getEnvIntMin(name string, defaultValue int, min int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: %w", name, raw, err)
	}
	if value < min {
		return 0, fmt.Errorf("invalid %s value %d: must be >= %d", name, value, min)
	}
	return value, nil
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, 4)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out, nil
	}

	for _, part := range strings.Split(trimmed, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}

		if _, network, err := net.ParseCIDR(value); err == nil {
			out = append(out, network)
			continue
		}

		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid GATEWAY_TRUSTED_PROXY_CIDRS entry %q: expected CIDR or IP", value)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		mask := net.CIDRMask(bits, bits)
		out = append(out, &net.IPNet{
			IP:   ip.Mask(mask),
			Mask: mask,
		})
	}

	return out, nil
}

func parseAllowedOrigins(raw string) (map[string]struct{}, error) {
	out := parseCSVSet(raw)
	for origin := range out {
		parsed, err := url.Parse(origin)
		if err != nil {
			return nil, fmt.Errorf("invalid GATEWAY_ALLOWED_ORIGINS entry %q: %w", origin, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("invalid GATEWAY_ALLOWED_ORIGINS entry %q: expected http or https origin", origin)
		}
		if parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid GATEWAY_ALLOWED_ORIGINS entry %q: expected origin format scheme://host[:port]", origin)
		}
	}
	return out, nil
}

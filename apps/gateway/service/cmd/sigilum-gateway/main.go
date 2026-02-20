package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sigilum.local/gateway/config"
	"sigilum.local/gateway/internal/catalog"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
)

const (
	headerSignatureInput   = "signature-input"
	headerSignature        = "signature"
	headerNamespace        = "sigilum-namespace"
	headerSubject          = "sigilum-subject"
	headerAgentKey         = "sigilum-agent-key"
	headerAgentCert        = "sigilum-agent-cert"
	slackAliasConnectionID = "slack-proxy"
)

var (
	errInvalidSignatureInputFormat = errors.New("invalid Signature-Input header format")
	errInvalidSignedComponentSet   = errors.New("invalid signed component set")
)

type healthResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	DocsURL   string `json:"docs_url,omitempty"`
}

type testResponse struct {
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Error      string `json:"error,omitempty"`
}

type authorizedIdentity struct {
	Namespace string
	Subject   string
	PublicKey string
}

type mcpToolCallRequest struct {
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("failed to create data directory %q: %v", cfg.DataDir, err)
	}

	connectorService, err := connectors.NewService(cfg.DataDir, cfg.MasterKey)
	if err != nil {
		log.Fatalf("failed to initialize connector service: %v", err)
	}
	defer func() {
		if err := connectorService.Close(); err != nil {
			log.Printf("warning: failed to close connector store: %v", err)
		}
	}()

	catalogStore := catalog.NewStore(cfg.ServiceCatalogFile)
	if _, err := catalogStore.Load(); err != nil {
		log.Fatalf("failed to initialize service catalog: %v", err)
	}

	nonceStorePath := filepath.Join(cfg.DataDir, "nonce-replay-cache.json")
	nonceCache := newNonceReplayCache(cfg.NonceTTL, nonceStorePath)
	claimsCache, err := claimcache.NewCache(claimcache.CacheConfig{
		APIBaseURL:      cfg.RegistryURL,
		SignerNamespace: cfg.SigilumNamespace,
		SignerHomeDir:   cfg.SigilumHomeDir,
		RequestTimeout:  cfg.RegistryRequestTimeout,
		CacheTTL:        cfg.ClaimsCacheTTL,
		RefreshInterval: cfg.ClaimsCacheRefreshInterval,
		ResolveServiceAPIKey: func(service string) string {
			return resolveServiceAPIKey(service, cfg.ServiceAPIKey, cfg.SigilumHomeDir)
		},
		Logger:            log.Printf,
		MaxApprovedClaims: cfg.ClaimsCacheMaxApproved,
	})
	if err != nil {
		log.Fatalf("failed to initialize claims cache: %v", err)
	}
	claimsCache.Start()
	defer claimsCache.Close()
	mcpClient := mcpruntime.NewClient(20 * time.Second)

	mux := http.NewServeMux()
	registerHealthRoute(mux, cfg)
	registerMetricsRoute(mux, cfg)
	registerAdminRoutes(mux, cfg, connectorService, catalogStore, mcpClient)
	registerRuntimeRoutes(mux, cfg, nonceCache, claimsCache, connectorService, mcpClient)
	registerRootRoute(mux)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withRequestID(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("gateway listening addr=%s", cfg.Addr)
	log.Printf(
		"gateway security registry=%s timestamp_tolerance=%s nonce_ttl=%s auto_register_claims=%t require_signed_admin_checks=%t admin_access_mode=%s admin_token_configured=%t allow_unsigned_proxy=%t allow_unsigned_connections=%s trusted_proxy_cidrs=%s",
		cfg.RegistryURL,
		cfg.TimestampTolerance,
		cfg.NonceTTL,
		cfg.AutoRegisterClaims,
		cfg.RequireSignedAdminChecks,
		cfg.AdminAccessMode,
		strings.TrimSpace(cfg.AdminToken) != "",
		cfg.AllowUnsignedProxy,
		joinAllowedConnections(cfg.AllowUnsignedFor),
		joinTrustedProxyCIDRs(cfg.TrustedProxyCIDRs),
	)
	log.Printf("gateway replay protection storage=file nonce_ttl=%s nonce_store=%s", cfg.NonceTTL, nonceStorePath)
	log.Printf(
		"gateway runtime claims_cache_ttl=%s claims_refresh_interval=%s max_request_body_bytes=%d shutdown_timeout=%s slack_alias_connection_id=%s rotation_enforcement=%s rotation_grace=%s log_proxy_requests=%t",
		cfg.ClaimsCacheTTL,
		cfg.ClaimsCacheRefreshInterval,
		cfg.MaxRequestBodyBytes,
		cfg.ShutdownTimeout,
		slackAliasConnectionID,
		cfg.RotationEnforcement,
		cfg.RotationGracePeriod,
		cfg.LogProxyRequests,
	)
	log.Printf(
		"gateway storage data_dir=%s catalog=%s allowed_origins=%s",
		cfg.DataDir,
		cfg.ServiceCatalogFile,
		joinAllowedOrigins(cfg.AllowedOrigins),
	)

	serverCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case <-serverCtx.Done():
		log.Printf("shutdown signal received; draining for up to %s", cfg.ShutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
			if closeErr := srv.Close(); closeErr != nil {
				log.Printf("forced server close failed: %v", closeErr)
			}
		}

		if err := <-serverErrCh; err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error during shutdown: %v", err)
		}
	}
}

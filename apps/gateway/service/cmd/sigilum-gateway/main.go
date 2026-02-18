package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
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

type nonceReplayCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	nonces    map[string]time.Time
	lastSweep time.Time
}

func newNonceReplayCache(ttl time.Duration) *nonceReplayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &nonceReplayCache{
		ttl:    ttl,
		nonces: map[string]time.Time{},
	}
}

func (c *nonceReplayCache) Seen(namespace string, nonce string, now time.Time) bool {
	namespace = strings.TrimSpace(namespace)
	nonce = strings.TrimSpace(nonce)
	if namespace == "" || nonce == "" {
		return false
	}
	key := namespace + "\x00" + nonce
	expiresAt := now.Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	if now.Sub(c.lastSweep) > time.Minute {
		for k, expiry := range c.nonces {
			if !expiry.After(now) {
				delete(c.nonces, k)
			}
		}
		c.lastSweep = now
	}

	if existing, ok := c.nonces[key]; ok && existing.After(now) {
		return true
	}
	c.nonces[key] = expiresAt
	return false
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

	nonceCache := newNonceReplayCache(cfg.NonceTTL)
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
		Logger: log.Printf,
	})
	if err != nil {
		log.Fatalf("failed to initialize claims cache: %v", err)
	}
	claimsCache.Start()
	defer claimsCache.Close()
	mcpClient := mcpruntime.NewClient(20 * time.Second)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	})

	mux.HandleFunc("/api/admin/connections", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := connectorService.ListConnections()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list connections"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"connections": list})
		case http.MethodPost:
			var input connectors.CreateConnectionInput
			if err := readJSONBody(r, &input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}

			conn, err := connectorService.CreateConnection(input)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, connectors.ErrConnectionExists) {
					status = http.StatusConflict
				}
				writeJSON(w, status, errorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, conn)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/admin/connections/", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		resource := strings.TrimPrefix(r.URL.Path, "/api/admin/connections/")
		parts := strings.Split(strings.Trim(resource, "/"), "/")
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "connection id is required"})
			return
		}
		connectionID := parts[0]

		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				conn, err := connectorService.GetConnection(connectionID)
				if err != nil {
					writeConnectionError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, conn)
			case http.MethodDelete:
				if err := connectorService.DeleteConnection(connectionID); err != nil {
					writeConnectionError(w, err)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPatch:
				var input connectors.UpdateConnectionInput
				if err := readJSONBody(r, &input); err != nil {
					writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
					return
				}
				conn, err := connectorService.UpdateConnection(connectionID, input)
				if err != nil {
					writeConnectionError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, conn)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}

		action := parts[1]
		switch action {
		case "rotate":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var input connectors.RotateSecretInput
			if err := readJSONBody(r, &input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}
			conn, err := connectorService.RotateSecret(connectionID, input)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, conn)
		case "test":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var input connectors.TestConnectionInput
			if err := readJSONBody(r, &input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}
			status, statusCode, testErr := runConnectionTest(r.Context(), connectorService, mcpClient, connectionID, input)
			if recordErr := connectorService.RecordTestResult(connectionID, status, statusCode, testErr); recordErr != nil {
				log.Printf("warning: failed to record test result for %s: %v", connectionID, recordErr)
			}

			responseCode := http.StatusOK
			if status != "pass" && statusCode == 0 {
				responseCode = http.StatusBadGateway
			}
			writeJSON(w, responseCode, testResponse{
				Status:     status,
				HTTPStatus: statusCode,
				Error:      testErr,
			})
		case "discover":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			conn, err := connectorService.GetConnection(connectionID)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			if !isMCPConnection(conn) {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "connection protocol is not mcp"})
				return
			}
			proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			discovery, err := mcpClient.Discover(r.Context(), proxyCfg)
			if err != nil {
				conn.MCPDiscovery.LastDiscoveredAt = time.Now().UTC().Format(time.RFC3339Nano)
				conn.MCPDiscovery.LastDiscoveryError = err.Error()
				if _, saveErr := connectorService.SaveMCPDiscovery(connectionID, conn.MCPDiscovery); saveErr != nil {
					log.Printf("warning: failed to persist mcp discovery error for %s: %v", connectionID, saveErr)
				}
				writeJSON(w, http.StatusBadGateway, errorResponse{
					Error: fmt.Sprintf("mcp discovery failed: %v", err),
					Code:  "MCP_DISCOVERY_FAILED",
				})
				return
			}
			updated, err := connectorService.SaveMCPDiscovery(connectionID, discovery)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, updated.MCPDiscovery)
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api/admin/credential-variables", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		switch r.Method {
		case http.MethodGet:
			values, err := connectorService.ListCredentialVariables()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list credential variables"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"variables": values})
		case http.MethodPost:
			var input connectors.UpsertSharedCredentialVariableInput
			if err := readJSONBody(r, &input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}
			if subject := strings.TrimSpace(r.Header.Get(headerSubject)); subject != "" {
				input.CreatedBySubject = subject
			}
			value, err := connectorService.UpsertCredentialVariable(input)
			if err != nil {
				writeCredentialVariableError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, value)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/admin/credential-variables/", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		key := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/admin/credential-variables/"))
		if key == "" {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "variable key is required"})
			return
		}

		switch r.Method {
		case http.MethodDelete:
			if err := connectorService.DeleteCredentialVariable(key); err != nil {
				writeCredentialVariableError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "key": key})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/admin/service-catalog", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodGet:
			payload, err := catalogStore.Load()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("failed to load service catalog: %v", err)})
				return
			}
			writeJSON(w, http.StatusOK, payload)
		case http.MethodPut:
			var input catalog.ServiceCatalog
			if err := readJSONBody(r, &input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}
			if err := catalogStore.Save(input); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
				return
			}
			payload, err := catalogStore.Load()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("failed to load updated service catalog: %v", err)})
				return
			}
			writeJSON(w, http.StatusOK, payload)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	})
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		handleMCPRequest(w, r, nonceCache, claimsCache, connectorService, mcpClient, cfg)
	})
	mux.HandleFunc("/slack", func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	})
	mux.HandleFunc("/slack/", func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("sigilum-gateway"))
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("sigilum-gateway listening on %s", cfg.Addr)
	log.Printf(
		"registry=%s timestamp_tolerance=%s nonce_ttl=%s claims_cache_ttl=%s claims_refresh_interval=%s slack_alias_connection_id=%s rotation_enforcement=%s rotation_grace=%s catalog=%s log_proxy_requests=%t allow_unsigned_proxy=%t allow_unsigned_connections=%s trusted_proxy_cidrs=%s allowed_origins=%s",
		cfg.RegistryURL,
		cfg.TimestampTolerance,
		cfg.NonceTTL,
		cfg.ClaimsCacheTTL,
		cfg.ClaimsCacheRefreshInterval,
		slackAliasConnectionID,
		cfg.RotationEnforcement,
		cfg.RotationGracePeriod,
		cfg.ServiceCatalogFile,
		cfg.LogProxyRequests,
		cfg.AllowUnsignedProxy,
		joinAllowedConnections(cfg.AllowUnsignedFor),
		joinTrustedProxyCIDRs(cfg.TrustedProxyCIDRs),
		joinAllowedOrigins(cfg.AllowedOrigins),
	)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigilum.local/gateway/config"
	"sigilum.local/gateway/internal/catalog"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/gateway/internal/connectors"
	mcpruntime "sigilum.local/gateway/internal/mcp"
)

func registerHealthRoute(
	mux *http.ServeMux,
	cfg config.Config,
	connectorService *connectors.Service,
) {
	writeHealth := func(w http.ResponseWriter, r *http.Request, check string, statusCode int, status string) {
		writeJSON(w, statusCode, map[string]any{
			"status": status,
			"check":  check,
		})
	}

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeHealth(w, r, "health", http.StatusOK, "ok")
	})

	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeHealth(w, r, "liveness", http.StatusOK, "ok")
	})

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		if connectorService == nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{
				Error: "gateway dependencies are not initialized",
				Code:  "NOT_READY",
			})
			return
		}
		if _, err := connectorService.ListConnections(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{
				Error: "gateway dependencies are not ready",
				Code:  "NOT_READY",
			})
			return
		}
		writeHealth(w, r, "readiness", http.StatusOK, "ok")
	})
}

func registerMetricsRoute(mux *http.ServeMux, cfg config.Config) {
	mux.HandleFunc("/metrics", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(gatewayMetricRegistry.renderPrometheus()))
	}))
}

func registerAdminRoutes(
	mux *http.ServeMux,
	cfg config.Config,
	connectorService *connectors.Service,
	catalogStore *catalog.Store,
	mcpClient *mcpruntime.Client,
) {
	mux.HandleFunc("/api/admin/connections", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
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
			if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
				writeJSONBodyError(w, err)
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
			maybePrewarmMCPDiscovery(conn.ID, conn, connectorService, mcpClient)
			writeJSON(w, http.StatusCreated, conn)
		default:
			writeMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/admin/connections/", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
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
				if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
					writeJSONBodyError(w, err)
					return
				}
				conn, err := connectorService.UpdateConnection(connectionID, input)
				if err != nil {
					writeConnectionError(w, err)
					return
				}
				maybePrewarmMCPDiscovery(connectionID, conn, connectorService, mcpClient)
				writeJSON(w, http.StatusOK, conn)
			default:
				writeMethodNotAllowed(w)
			}
			return
		}

		action := parts[1]
		switch action {
		case "rotate":
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w)
				return
			}
			var input connectors.RotateSecretInput
			if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
				writeJSONBodyError(w, err)
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
				writeMethodNotAllowed(w)
				return
			}
			body, err := readLimitedRequestBody(r, cfg.MaxRequestBodyBytes)
			if err != nil {
				writeRequestBodyError(w, err)
				return
			}
			var input connectors.TestConnectionInput
			if len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, &input); err != nil {
					writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid JSON body: %v", err)})
					return
				}
			}
			status, statusCode, testErr := runConnectionTest(r.Context(), connectorService, mcpClient, connectionID, input)
			if recordErr := connectorService.RecordTestResult(connectionID, status, statusCode, testErr); recordErr != nil {
				log.Printf("warning: failed to record test result for %s: %v", connectionID, recordErr)
			}
			if status != "pass" {
				log.Printf("connection test failed connection=%s status_code=%d error=%s", connectionID, statusCode, testErr)
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
				writeMethodNotAllowed(w)
				return
			}
			conn, err := connectorService.GetConnection(connectionID)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			if !connectors.IsMCPConnection(conn) {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "connection protocol is not mcp"})
				return
			}
			proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
			if err != nil {
				writeConnectionError(w, err)
				return
			}
			refreshMode, err := parseMCPDiscoveryRefreshMode(r.URL.Query().Get("refresh"), mcpDiscoveryRefreshModeForce)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{
					Error: err.Error(),
					Code:  "INVALID_REFRESH_MODE",
				})
				return
			}
			discoveryStart := time.Now()
			resolution, err := resolveMCPDiscovery(
				r.Context(),
				connectionID,
				proxyCfg,
				connectorService,
				mcpClient,
				cfg.MCPDiscoveryCacheTTL,
				cfg.MCPDiscoveryStaleIfError,
				refreshMode,
				discoveryStart,
			)
			if err != nil {
				gatewayMetricRegistry.recordMCPDiscovery("error")
				gatewayMetricRegistry.observeUpstream("mcp", "error", time.Since(discoveryStart))
				gatewayMetricRegistry.recordUpstreamError("MCP_DISCOVERY_FAILED")
				writeJSON(w, http.StatusBadGateway, errorResponse{
					Error: fmt.Sprintf("mcp discovery failed: %v", err),
					Code:  "MCP_DISCOVERY_FAILED",
				})
				return
			}

			if resolution.AttemptedRefresh {
				if resolution.RefreshError != nil {
					gatewayMetricRegistry.recordMCPDiscovery(string(mcpDiscoverySourceStaleIfError))
					gatewayMetricRegistry.observeUpstream("mcp", "error", time.Since(discoveryStart))
					gatewayMetricRegistry.recordUpstreamError("MCP_DISCOVERY_FAILED")
				} else {
					gatewayMetricRegistry.recordMCPDiscovery("success")
					gatewayMetricRegistry.observeUpstream("mcp", "success", time.Since(discoveryStart))
				}
			} else {
				gatewayMetricRegistry.recordMCPDiscovery(string(resolution.Source))
			}
			if resolution.Source != "" {
				w.Header().Set("X-Sigilum-MCP-Discovery", string(resolution.Source))
			}
			writeJSON(w, http.StatusOK, resolution.Connection.MCPDiscovery)
		default:
			writeNotFound(w, "admin action not found")
		}
	}))

	mux.HandleFunc("/api/admin/credential-variables", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
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
			if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
				writeJSONBodyError(w, err)
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
			writeMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/admin/credential-variables/", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
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
			writeMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/admin/openclaw/legacy-keys", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, discoverLegacyOpenClawKeys(connectorService))
		default:
			writeMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/admin/openclaw/legacy-keys/import", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var input legacyKeyImportRequest
		if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
			writeJSONBodyError(w, err)
			return
		}
		response, err := importLegacyOpenClawKeys(connectorService, catalogStore, input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, response)
	}))

	mux.HandleFunc("/api/admin/openclaw/legacy-keys/purge", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var input legacyKeyPurgeRequest
		if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
			writeJSONBodyError(w, err)
			return
		}
		response, err := purgeLegacyOpenClawKeys(input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, response)
	}))

	mux.HandleFunc("/api/admin/service-api-keys/", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
			return
		}
		connectionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/admin/service-api-keys/"))
		if connectionID == "" || !isSafeServiceKeyID(connectionID) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "valid connection id is required"})
			return
		}
		switch r.Method {
		case http.MethodPut:
			var input struct {
				Key string `json:"key"`
			}
			if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
				writeJSONBodyError(w, err)
				return
			}
			key := strings.TrimSpace(input.Key)
			if key == "" {
				writeJSON(w, http.StatusBadRequest, errorResponse{Error: "key is required"})
				return
			}
			homeDir := strings.TrimSpace(cfg.SigilumHomeDir)
			if homeDir == "" {
				homeDir = strings.TrimSpace(os.Getenv("SIGILUM_HOME"))
			}
			if homeDir == "" {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "SIGILUM_HOME is not configured"})
				return
			}
			if err := os.MkdirAll(homeDir, 0o700); err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("failed to create sigilum home: %v", err)})
				return
			}
			keyFile := filepath.Join(homeDir, "service-api-key-"+connectionID)
			if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("failed to write key file: %v", err)})
				return
			}
			log.Printf("service API key written for connection=%s file=%s", connectionID, keyFile)
			writeJSON(w, http.StatusOK, map[string]any{"connection_id": connectionID, "written": true})
		case http.MethodGet:
			key := resolveServiceAPIKey(connectionID, cfg.ServiceAPIKey, cfg.SigilumHomeDir)
			writeJSON(w, http.StatusOK, map[string]any{
				"connection_id": connectionID,
				"has_key":       key != "",
				"key_prefix":    truncateKeyPrefix(key, 8),
			})
		default:
			writeMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/admin/service-catalog", withRequestTimeout(cfg.AdminRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r, cfg.AllowedOrigins)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !enforceAdminRequestAccess(w, r, cfg) {
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
			if err := readJSONBody(r, &input, cfg.MaxRequestBodyBytes); err != nil {
				writeJSONBodyError(w, err)
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
			writeMethodNotAllowed(w)
		}
	}))
}

func registerRuntimeRoutes(
	mux *http.ServeMux,
	cfg config.Config,
	nonceCache *nonceReplayCache,
	claimsCache *claimcache.Cache,
	connectorService *connectors.Service,
	mcpClient *mcpruntime.Client,
) {
	mux.HandleFunc("/proxy/", withRequestTimeout(cfg.ProxyRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	}))
	mux.HandleFunc("/mcp/", withRequestTimeout(cfg.MCPRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		handleMCPRequest(w, r, nonceCache, claimsCache, connectorService, mcpClient, cfg)
	}))
	mux.HandleFunc("/slack", withRequestTimeout(cfg.ProxyRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	}))
	mux.HandleFunc("/slack/", withRequestTimeout(cfg.ProxyRequestTimeout, func(w http.ResponseWriter, r *http.Request) {
		handleProxyRequest(w, r, nonceCache, claimsCache, connectorService, cfg)
	}))
}

func registerRootRoute(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("sigilum-gateway"))
	})
}

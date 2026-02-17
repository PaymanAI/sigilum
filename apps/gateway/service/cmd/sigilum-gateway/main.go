package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"sigilum.local/gateway/config"
	"sigilum.local/gateway/internal/catalog"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/gateway/internal/connectors"
	"sigilum.local/sdk-go/sigilum"
)

const (
	headerSignatureInput   = "signature-input"
	headerSignature        = "signature"
	headerNamespace        = "sigilum-namespace"
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
			return resolveServiceAPIKey(service, cfg.ServiceAPIKey)
		},
		Logger: log.Printf,
	})
	if err != nil {
		log.Fatalf("failed to initialize claims cache: %v", err)
	}
	claimsCache.Start()
	defer claimsCache.Close()

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
			status, statusCode, testErr := runConnectionTest(connectorService, connectionID, input)
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
		default:
			http.NotFound(w, r)
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

func handleProxyRequest(
	w http.ResponseWriter,
	r *http.Request,
	nonceCache *nonceReplayCache,
	claimsCache *claimcache.Cache,
	connectorService *connectors.Service,
	cfg config.Config,
) {
	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	connectionID, upstreamPath, ok := resolveProxyRoute(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "invalid proxy path, expected /proxy/{connection_id}/... or /slack/...",
		})
		return
	}
	start := time.Now()
	remoteIP := clientIP(r, cfg.TrustedProxyCIDRs)
	if cfg.LogProxyRequests {
		log.Printf(
			"proxy request start method=%s connection=%s path=%s query=%q remote_ip=%s signed_headers=%t",
			r.Method,
			connectionID,
			upstreamPath,
			r.URL.RawQuery,
			remoteIP,
			hasSigilumHeaders(r.Header),
		)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "failed to read request body"})
		return
	}
	_ = r.Body.Close()

	allowUnsigned := cfg.AllowUnsignedProxy && isAllowedUnsignedConnection(cfg.AllowUnsignedFor, connectionID)
	if !allowUnsigned {
		headers := r.Header.Clone()
		signatureResult := sigilum.VerifyHTTPSignature(sigilum.VerifySignatureInput{
			URL:           requestAbsoluteURL(r, cfg.TrustedProxyCIDRs),
			Method:        r.Method,
			Headers:       headersToMap(headers),
			Body:          body,
			MaxAgeSeconds: int64(cfg.TimestampTolerance / time.Second),
		})
		if !signatureResult.Valid {
			writeVerificationFailure(w, signatureResult, cfg.LogProxyRequests, connectionID, remoteIP)
			return
		}
		if componentErr := validateSignatureComponents(headers.Get(headerSignatureInput), len(body) > 0); componentErr != nil {
			if cfg.LogProxyRequests {
				log.Printf("proxy request component validation failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, componentErr)
			}
			writeProxyAuthFailure(w)
			return
		}

		namespace, publicKey, identityErr := extractSigilumIdentity(headers)
		if identityErr != nil {
			if cfg.LogProxyRequests {
				log.Printf("proxy request identity extraction failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, identityErr)
			}
			writeProxyAuthFailure(w)
			return
		}
		nonce, nonceErr := extractSignatureNonce(headers.Get(headerSignatureInput))
		if nonceErr != nil {
			if cfg.LogProxyRequests {
				log.Printf("proxy request nonce extraction failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, nonceErr)
			}
			writeProxyAuthFailure(w)
			return
		}
		if nonceCache != nil && nonceCache.Seen(namespace, nonce, time.Now().UTC()) {
			if cfg.LogProxyRequests {
				log.Printf("proxy request replay detected connection=%s remote_ip=%s namespace=%s", connectionID, remoteIP, namespace)
			}
			writeProxyAuthFailure(w)
			return
		}
		approved, claimErr := claimsCache.IsApproved(r.Context(), connectionID, namespace, publicKey)
		if claimErr != nil {
			if cfg.LogProxyRequests {
				log.Printf("proxy request claim cache failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, claimErr)
			}
			writeProxyAuthFailure(w)
			return
		}
		if cfg.LogProxyRequests {
			log.Printf("proxy claim cache precheck connection=%s namespace=%s approved=%t", connectionID, namespace, approved)
		}
		if !approved {
			if cfg.LogProxyRequests {
				log.Printf("proxy request denied by claim cache connection=%s remote_ip=%s namespace=%s", connectionID, remoteIP, namespace)
			}
			writeProxyAuthFailure(w)
			return
		}
	} else if cfg.LogProxyRequests {
		log.Printf("proxy request auth bypass enabled connection=%s remote_ip=%s", connectionID, remoteIP)
	}

	proxyCfg, err := connectorService.ResolveProxyConfig(connectionID)
	if err != nil {
		writeConnectionError(w, err)
		return
	}
	if block, warning := evaluateRotationPolicy(proxyCfg.Connection, cfg.RotationEnforcement, cfg.RotationGracePeriod, time.Now().UTC()); block {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: warning,
			Code:  "ROTATION_REQUIRED",
		})
		return
	} else if warning != "" {
		w.Header().Set("X-Sigilum-Rotation-Warning", warning)
		log.Printf("rotation warning: connection=%s detail=%s", connectionID, warning)
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.RequestURI = ""

	proxy, err := connectors.NewReverseProxy(proxyCfg, upstreamPath, r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid target config: %v", err)})
		return
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		writeJSON(rw, http.StatusBadGateway, errorResponse{
			Error: "upstream request failed",
			Code:  "UPSTREAM_ERROR",
		})
		log.Printf("upstream request failed: connection=%s err=%v", connectionID, proxyErr)
	}

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(recorder, r)
	if cfg.LogProxyRequests {
		log.Printf(
			"proxy request end method=%s connection=%s status=%d duration=%s response_bytes=%d",
			r.Method,
			connectionID,
			recorder.status,
			time.Since(start).Round(time.Millisecond),
			recorder.bytesWritten,
		)
	}
}

func runConnectionTest(service *connectors.Service, connectionID string, input connectors.TestConnectionInput) (status string, httpStatus int, testErr string) {
	proxyCfg, err := service.ResolveProxyConfig(connectionID)
	if err != nil {
		return "fail", 0, err.Error()
	}

	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	testPath := strings.TrimSpace(input.TestPath)
	if testPath == "" {
		testPath = "/"
	}
	if !strings.HasPrefix(testPath, "/") {
		testPath = "/" + testPath
	}
	parsedTestPath, err := url.Parse(testPath)
	if err != nil {
		return "fail", 0, fmt.Sprintf("invalid test_path: %v", err)
	}

	target, err := url.Parse(proxyCfg.Connection.BaseURL)
	if err != nil {
		return "fail", 0, err.Error()
	}
	target.Path = joinPath(target.Path, proxyCfg.Connection.PathPrefix, parsedTestPath.Path)
	target.RawQuery = parsedTestPath.RawQuery

	body := strings.TrimSpace(input.Body)
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, target.String(), bodyReader)
	if err != nil {
		return "fail", 0, err.Error()
	}

	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	connectors.ApplyAuthHeader(req.Header, proxyCfg.Connection, proxyCfg.Secret)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "fail", 0, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "pass", resp.StatusCode, ""
	}
	bodyPreview, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if readErr != nil || len(bodyPreview) == 0 {
		return "fail", resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode)
	}
	message := compactMessage(string(bodyPreview))
	if message == "" {
		return "fail", resp.StatusCode, fmt.Sprintf("http %d", resp.StatusCode)
	}
	return "fail", resp.StatusCode, fmt.Sprintf("http %d: %s", resp.StatusCode, message)
}

func compactMessage(value string) string {
	compact := strings.Join(strings.Fields(value), " ")
	if compact == "" {
		return ""
	}
	const maxLen = 240
	if len(compact) <= maxLen {
		return compact
	}
	return compact[:maxLen] + "..."
}

func evaluateRotationPolicy(conn connectors.Connection, mode string, gracePeriod time.Duration, now time.Time) (bool, string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "off" {
		return false, ""
	}

	dueAtRaw := strings.TrimSpace(conn.NextRotationDueAt)
	if dueAtRaw == "" {
		return false, ""
	}
	dueAt, err := time.Parse(time.RFC3339Nano, dueAtRaw)
	if err != nil {
		return false, ""
	}

	effectiveDueAt := dueAt.Add(gracePeriod)
	if !now.After(effectiveDueAt) {
		return false, ""
	}

	message := fmt.Sprintf("connection %q secret rotation is overdue (due %s)", conn.ID, dueAt.UTC().Format(time.RFC3339))
	if mode == "block" {
		return true, message
	}
	return false, message
}

func resolveProxyRoute(requestPath string) (connectionID string, upstreamPath string, ok bool) {
	if strings.HasPrefix(requestPath, "/proxy/") {
		rest := strings.TrimPrefix(requestPath, "/proxy/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			return "", "", false
		}
		connectionID = parts[0]
		upstreamPath = "/"
		if len(parts) == 2 && parts[1] != "" {
			upstreamPath = "/" + parts[1]
		}
		return connectionID, upstreamPath, true
	}

	if requestPath == "/slack" || strings.HasPrefix(requestPath, "/slack/") {
		connectionID = slackAliasConnectionID
		upstreamPath = strings.TrimPrefix(requestPath, "/slack")
		if upstreamPath == "" {
			upstreamPath = "/"
		}
		if !strings.HasPrefix(upstreamPath, "/") {
			upstreamPath = "/" + upstreamPath
		}
		return connectionID, upstreamPath, true
	}

	return "", "", false
}

func resolveServiceAPIKey(connectionID string, defaultValue string) string {
	if scoped := strings.TrimSpace(os.Getenv("SIGILUM_SERVICE_API_KEY_" + serviceAPIKeyEnvSuffix(connectionID))); scoped != "" {
		return scoped
	}
	return strings.TrimSpace(defaultValue)
}

func serviceAPIKeyEnvSuffix(connectionID string) string {
	value := strings.TrimSpace(connectionID)
	if value == "" {
		return "DEFAULT"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 32)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	suffix := strings.Trim(builder.String(), "_")
	if suffix == "" {
		return "DEFAULT"
	}
	return suffix
}

func writeVerificationFailure(
	w http.ResponseWriter,
	result sigilum.VerifySignatureResult,
	logEnabled bool,
	connectionID string,
	remoteIP string,
) {
	if logEnabled {
		log.Printf("proxy request verify failed connection=%s remote_ip=%s reason=%s", connectionID, remoteIP, result.Reason)
	}
	writeProxyAuthFailure(w)
}

func extractSigilumIdentity(headers http.Header) (namespace string, publicKey string, err error) {
	namespace = strings.TrimSpace(headers.Get(headerNamespace))
	if namespace == "" {
		return "", "", fmt.Errorf("missing %s header", headerNamespace)
	}
	publicKey = strings.TrimSpace(headers.Get(headerAgentKey))
	if publicKey == "" {
		return "", "", fmt.Errorf("missing %s header", headerAgentKey)
	}
	return namespace, publicKey, nil
}

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

func hasSigilumHeaders(headers http.Header) bool {
	return strings.TrimSpace(headers.Get(headerSignatureInput)) != "" ||
		strings.TrimSpace(headers.Get(headerSignature)) != "" ||
		strings.TrimSpace(headers.Get(headerNamespace)) != "" ||
		strings.TrimSpace(headers.Get(headerAgentKey)) != "" ||
		strings.TrimSpace(headers.Get(headerAgentCert)) != ""
}

func headersToMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[key] = values[0]
	}
	return out
}

func requestAbsoluteURL(r *http.Request, trustedProxyCIDRs []*net.IPNet) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if isTrustedProxy(r.RemoteAddr, trustedProxyCIDRs) {
		if forwarded := firstCSVToken(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
			candidate := strings.ToLower(strings.TrimSpace(forwarded))
			if candidate == "http" || candidate == "https" {
				scheme = candidate
			}
		}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func extractSignatureNonce(signatureInput string) (string, error) {
	needle := `;nonce="`
	index := strings.Index(signatureInput, needle)
	if index < 0 {
		return "", errors.New("invalid signature-input: missing nonce")
	}
	start := index + len(needle)
	end := strings.Index(signatureInput[start:], `"`)
	if end < 0 {
		return "", errors.New("invalid signature-input: malformed nonce")
	}
	nonce := strings.TrimSpace(signatureInput[start : start+end])
	if nonce == "" {
		return "", errors.New("invalid signature-input: empty nonce")
	}
	return nonce, nil
}

func validateSignatureComponents(signatureInput string, hasBody bool) error {
	components, err := parseSignatureComponents(signatureInput)
	if err != nil {
		return err
	}

	expected := []string{"@method", "@target-uri", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"}
	if hasBody {
		expected = []string{"@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"}
	}
	if len(components) != len(expected) {
		return errInvalidSignedComponentSet
	}
	for idx := range expected {
		if components[idx] != expected[idx] {
			return errInvalidSignedComponentSet
		}
	}
	return nil
}

func parseSignatureComponents(signatureInput string) ([]string, error) {
	value := strings.TrimSpace(signatureInput)
	if value == "" {
		return nil, errInvalidSignatureInputFormat
	}
	const prefix = "sig1=("
	const createdMarker = ");created="
	if !strings.HasPrefix(value, prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	end := strings.Index(value, createdMarker)
	if end < 0 || end <= len(prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	raw := strings.TrimSpace(value[len(prefix):end])
	if raw == "" {
		return nil, errInvalidSignatureInputFormat
	}

	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		return nil, errInvalidSignatureInputFormat
	}

	components := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
			return nil, errInvalidSignatureInputFormat
		}
		component := strings.TrimSpace(token[1 : len(token)-1])
		if component == "" {
			return nil, errInvalidSignatureInputFormat
		}
		components = append(components, component)
	}
	return components, nil
}

func isAllowedUnsignedConnection(allow map[string]struct{}, connectionID string) bool {
	if len(allow) == 0 {
		return true
	}
	_, ok := allow[connectionID]
	return ok
}

func joinAllowedConnections(allow map[string]struct{}) string {
	if len(allow) == 0 {
		return "*"
	}
	values := make([]string, 0, len(allow))
	for connectionID := range allow {
		values = append(values, connectionID)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func joinTrustedProxyCIDRs(cidrs []*net.IPNet) string {
	if len(cidrs) == 0 {
		return "(none)"
	}
	values := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr == nil {
			continue
		}
		values = append(values, cidr.String())
	}
	if len(values) == 0 {
		return "(none)"
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func joinAllowedOrigins(allowedOrigins map[string]struct{}) string {
	if len(allowedOrigins) == 0 {
		return "(none)"
	}
	values := make([]string, 0, len(allowedOrigins))
	for origin := range allowedOrigins {
		values = append(values, origin)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
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

func readJSONBody(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return errors.New("failed to read request body")
	}
	if len(body) == 0 {
		return errors.New("request body is required")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func joinPath(paths ...string) string {
	parts := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		parts = append(parts, strings.Trim(p, "/"))
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins map[string]struct{}) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Vary", "Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func writeProxyAuthFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error: "request not authorized",
		Code:  "AUTH_FORBIDDEN",
	})
}

func clientIP(r *http.Request, trustedProxyCIDRs []*net.IPNet) string {
	if isTrustedProxy(r.RemoteAddr, trustedProxyCIDRs) {
		if forwarded := firstCSVToken(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return remoteAddrIPString(r.RemoteAddr)
}

func isTrustedProxy(remoteAddr string, trustedProxyCIDRs []*net.IPNet) bool {
	if len(trustedProxyCIDRs) == 0 {
		return false
	}
	ip := remoteAddrIP(remoteAddr)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedProxyCIDRs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func firstCSVToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	part := strings.Split(trimmed, ",")[0]
	return strings.TrimSpace(part)
}

func remoteAddrIP(remoteAddr string) net.IP {
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return nil
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

func remoteAddrIPString(remoteAddr string) string {
	ip := remoteAddrIP(remoteAddr)
	if ip != nil {
		return ip.String()
	}
	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return "127.0.0.1"
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 && strings.Count(host, ":") == 1 {
		return host[:idx]
	}
	return host
}

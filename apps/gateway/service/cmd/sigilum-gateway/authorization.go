package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"sigilum.local/gateway/config"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/sdk-go/sigilum"
)

type claimRegistrationAttempt struct {
	Enabled bool
	Result  claimcache.SubmitClaimResult
	Err     error
}

func authorizeConnectionRequest(
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	connectionID string,
	remoteIP string,
	nonceCache *nonceReplayCache,
	claimsCache *claimcache.Cache,
	cfg config.Config,
) (authorizedIdentity, bool) {
	requestID := requestIDFromContext(r.Context())
	if shouldBypassConnectionAuthorization(cfg, connectionID) {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_bypass", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"decision":    "allow",
			"reason_code": "ALLOW_UNSIGNED_CONNECTION",
		})
		return authorizedIdentity{}, true
	}

	headers := r.Header.Clone()
	if !verifySignedRequest(w, r, headers, body, connectionID, remoteIP, requestID, cfg) {
		return authorizedIdentity{}, false
	}

	identity, ok := resolveAuthorizedIdentity(w, headers, connectionID, remoteIP, requestID, cfg)
	if !ok {
		return authorizedIdentity{}, false
	}

	if !enforceNonceReplayProtection(w, headers, identity.Namespace, identity.Subject, connectionID, remoteIP, requestID, nonceCache, cfg) {
		return authorizedIdentity{}, false
	}

	if !enforceClaimAuthorization(w, r, claimsCache, connectionID, identity, remoteIP, requestID, cfg) {
		return authorizedIdentity{}, false
	}

	return identity, true
}

func shouldBypassConnectionAuthorization(cfg config.Config, connectionID string) bool {
	return cfg.AllowUnsignedProxy && isAllowedUnsignedConnection(cfg.AllowUnsignedFor, connectionID)
}

func verifySignedRequest(
	w http.ResponseWriter,
	r *http.Request,
	headers http.Header,
	body []byte,
	connectionID string,
	remoteIP string,
	requestID string,
	cfg config.Config,
) bool {
	if err := validateSigilumAuthHeaders(headers); err != nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"stage":       "header_validation",
			"decision":    "deny",
			"reason_code": codeAuthHeadersInvalid,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthHeadersInvalid, "invalid or duplicate signed headers")
		return false
	}

	signatureResult := sigilum.VerifyHTTPSignature(sigilum.VerifySignatureInput{
		URL:           requestAbsoluteURL(r, cfg.TrustedProxyCIDRs),
		Method:        r.Method,
		Headers:       headersToMap(headers),
		Body:          body,
		MaxAgeSeconds: int64(cfg.TimestampTolerance / time.Second),
	})
	if !signatureResult.Valid {
		writeVerificationFailure(w, signatureResult, cfg.LogProxyRequests, connectionID, remoteIP, requestID)
		return false
	}

	if componentErr := validateSignatureComponents(headers.Get(headerSignatureInput), len(body) > 0); componentErr != nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"stage":       "component_validation",
			"decision":    "deny",
			"reason_code": codeAuthSignedComponents,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthSignedComponents, "invalid signed component set")
		return false
	}
	return true
}

func resolveAuthorizedIdentity(
	w http.ResponseWriter,
	headers http.Header,
	connectionID string,
	remoteIP string,
	requestID string,
	cfg config.Config,
) (authorizedIdentity, bool) {
	namespace, publicKey, subject, identityErr := extractSigilumIdentity(headers)
	if identityErr != nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"stage":       "identity_extraction",
			"decision":    "deny",
			"reason_code": codeAuthIdentityInvalid,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthIdentityInvalid, "invalid Sigilum identity headers")
		return authorizedIdentity{}, false
	}
	logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_identity_resolved", map[string]any{
		"request_id": requestID,
		"connection": connectionID,
		"namespace":  namespace,
		"subject":    subject,
		"decision":   "allow",
	})
	return authorizedIdentity{
		Namespace: namespace,
		Subject:   subject,
		PublicKey: publicKey,
	}, true
}

func enforceNonceReplayProtection(
	w http.ResponseWriter,
	headers http.Header,
	namespace string,
	subject string,
	connectionID string,
	remoteIP string,
	requestID string,
	nonceCache *nonceReplayCache,
	cfg config.Config,
) bool {
	nonce, nonceErr := extractSignatureNonce(headers.Get(headerSignatureInput))
	if nonceErr != nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"namespace":   namespace,
			"subject":     subject,
			"remote_ip":   remoteIP,
			"stage":       "nonce_validation",
			"decision":    "deny",
			"reason_code": codeAuthNonceInvalid,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthNonceInvalid, "invalid signature nonce")
		return false
	}
	if nonceCache != nil && nonceCache.Seen(namespace, nonce, time.Now().UTC()) {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"namespace":   namespace,
			"subject":     subject,
			"stage":       "replay_detection",
			"decision":    "deny",
			"reason_code": codeAuthReplayDetected,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthReplayDetected, "replay detected")
		return false
	}
	return true
}

func enforceClaimAuthorization(
	w http.ResponseWriter,
	r *http.Request,
	claimsCache *claimcache.Cache,
	connectionID string,
	identity authorizedIdentity,
	remoteIP string,
	requestID string,
	cfg config.Config,
) bool {
	if claimsCache == nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"namespace":   identity.Namespace,
			"subject":     identity.Subject,
			"stage":       "claims_cache",
			"decision":    "deny",
			"reason_code": codeAuthClaimsUnavailable,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthClaimsUnavailable, "claims authorization cache is unavailable")
		return false
	}

	approved, claimErr := claimsCache.IsApproved(r.Context(), connectionID, identity.Namespace, identity.PublicKey)
	if claimErr != nil {
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"namespace":   identity.Namespace,
			"subject":     identity.Subject,
			"stage":       "claims_lookup",
			"decision":    "deny",
			"reason_code": codeAuthClaimsLookupFailed,
		})
		writeProxyAuthError(w, http.StatusForbidden, codeAuthClaimsLookupFailed, "claims lookup failed")
		return false
	}

	logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_claim_precheck", map[string]any{
		"request_id": requestID,
		"connection": connectionID,
		"namespace":  identity.Namespace,
		"subject":    identity.Subject,
		"approved":   approved,
	})
	if !approved {
		claimAttempt := claimRegistrationAttempt{
			Enabled: cfg.AutoRegisterClaims,
		}
		if cfg.AutoRegisterClaims {
			if !allowClaimRegistration(connectionID, identity.Namespace) {
				logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_claim_submit", map[string]any{
					"request_id":  requestID,
					"connection":  connectionID,
					"namespace":   identity.Namespace,
					"subject":     identity.Subject,
					"remote_ip":   remoteIP,
					"decision":    "deny",
					"reason_code": codeAuthClaimSubmitRateLimited,
				})
				writeProxyAuthError(
					w,
					http.StatusTooManyRequests,
					codeAuthClaimSubmitRateLimited,
					"claim registration rate limit exceeded for this connection and namespace; retry in one minute",
				)
				return false
			}

			submitResult, submitErr := claimsCache.SubmitClaim(r.Context(), claimcache.SubmitClaimInput{
				Service:   connectionID,
				Namespace: identity.Namespace,
				PublicKey: identity.PublicKey,
				AgentIP:   remoteIP,
				Subject:   identity.Subject,
			})
			claimAttempt.Result = submitResult
			claimAttempt.Err = submitErr
			if submitErr != nil {
				logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_claim_submit", map[string]any{
					"request_id":  requestID,
					"connection":  connectionID,
					"namespace":   identity.Namespace,
					"subject":     identity.Subject,
					"remote_ip":   remoteIP,
					"decision":    "error",
					"reason_code": "CLAIM_SUBMIT_FAILED",
				})
			} else {
				logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_claim_submit", map[string]any{
					"request_id":   requestID,
					"connection":   connectionID,
					"namespace":    identity.Namespace,
					"subject":      identity.Subject,
					"remote_ip":    remoteIP,
					"claim_id":     submitResult.ClaimID,
					"claim_status": submitResult.Status,
					"http_status":  submitResult.HTTPStatus,
					"reason_code":  submitResult.Code,
				})
			}
		}
		logGatewayDecisionIf(cfg.LogProxyRequests, "proxy_auth_denied", map[string]any{
			"request_id":  requestID,
			"connection":  connectionID,
			"remote_ip":   remoteIP,
			"namespace":   identity.Namespace,
			"subject":     identity.Subject,
			"stage":       "claims_authorization",
			"decision":    "deny",
			"reason_code": codeAuthClaimRequired,
		})
		writeProxyAuthRequiredMarkdown(w, proxyAuthRequiredMarkdownInput{
			Namespace:         identity.Namespace,
			Subject:           identity.Subject,
			PublicKey:         identity.PublicKey,
			Service:           connectionID,
			RemoteIP:          remoteIP,
			ClaimRegistration: claimAttempt,
		})
		return false
	}
	return true
}

func enforceAdminRequestAccess(w http.ResponseWriter, r *http.Request, cfg config.Config) bool {
	if !cfg.RequireSignedAdminChecks {
		return true
	}
	requestID := requestIDFromContext(r.Context())
	mode := strings.ToLower(strings.TrimSpace(cfg.AdminAccessMode))
	if mode == "" {
		mode = config.AdminAccessModeHybrid
	}
	adminToken := strings.TrimSpace(cfg.AdminToken)
	remoteIP := clientIP(r, cfg.TrustedProxyCIDRs)

	switch mode {
	case config.AdminAccessModeToken:
		if adminToken == "" {
			logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_denied", map[string]any{
				"request_id":  requestID,
				"mode":        mode,
				"path":        r.URL.Path,
				"method":      r.Method,
				"remote_ip":   remoteIP,
				"decision":    "deny",
				"reason_code": "ADMIN_TOKEN_NOT_CONFIGURED",
			})
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error: "admin token mode requires GATEWAY_ADMIN_TOKEN",
				Code:  "ADMIN_TOKEN_NOT_CONFIGURED",
			})
			return false
		}
		if hasAdminToken(r, adminToken) {
			logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_granted", map[string]any{
				"request_id": requestID,
				"mode":       mode,
				"path":       r.URL.Path,
				"method":     r.Method,
				"decision":   "allow",
				"via":        "token",
			})
			return true
		}
		logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_denied", map[string]any{
			"request_id":  requestID,
			"mode":        mode,
			"path":        r.URL.Path,
			"method":      r.Method,
			"remote_ip":   remoteIP,
			"decision":    "deny",
			"reason_code": "ADMIN_TOKEN_REQUIRED",
		})
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: "admin endpoints require a valid admin token",
			Code:  "ADMIN_TOKEN_REQUIRED",
		})
		return false
	case config.AdminAccessModeLoopback:
		if isLoopbackClient(remoteIP) {
			logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_granted", map[string]any{
				"request_id": requestID,
				"mode":       mode,
				"path":       r.URL.Path,
				"method":     r.Method,
				"remote_ip":  remoteIP,
				"decision":   "allow",
				"via":        "loopback",
			})
			return true
		}
		logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_denied", map[string]any{
			"request_id":  requestID,
			"mode":        mode,
			"path":        r.URL.Path,
			"method":      r.Method,
			"remote_ip":   remoteIP,
			"decision":    "deny",
			"reason_code": "ADMIN_LOOPBACK_REQUIRED",
		})
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: "admin endpoints require loopback client access",
			Code:  "ADMIN_LOOPBACK_REQUIRED",
		})
		return false
	default:
		if adminToken != "" && hasAdminToken(r, adminToken) {
			logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_granted", map[string]any{
				"request_id": requestID,
				"mode":       mode,
				"path":       r.URL.Path,
				"method":     r.Method,
				"decision":   "allow",
				"via":        "token",
			})
			return true
		}
		if isLoopbackClient(remoteIP) {
			logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_granted", map[string]any{
				"request_id": requestID,
				"mode":       mode,
				"path":       r.URL.Path,
				"method":     r.Method,
				"remote_ip":  remoteIP,
				"decision":   "allow",
				"via":        "loopback",
			})
			return true
		}
		logGatewayDecisionIf(cfg.LogProxyRequests, "admin_access_denied", map[string]any{
			"request_id":  requestID,
			"mode":        mode,
			"path":        r.URL.Path,
			"method":      r.Method,
			"remote_ip":   remoteIP,
			"decision":    "deny",
			"reason_code": "ADMIN_TOKEN_OR_LOOPBACK_REQUIRED",
		})
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: "admin endpoints require loopback access or a valid admin token",
			Code:  "ADMIN_TOKEN_OR_LOOPBACK_REQUIRED",
		})
		return false
	}
}

func hasAdminToken(r *http.Request, expectedToken string) bool {
	if r == nil {
		return false
	}
	token := strings.TrimSpace(expectedToken)
	if token == "" {
		return false
	}
	if headerToken := strings.TrimSpace(r.Header.Get("X-Sigilum-Admin-Token")); secureEqual(headerToken, token) {
		return true
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		bearerToken := strings.TrimSpace(authHeader[len("Bearer "):])
		if secureEqual(bearerToken, token) {
			return true
		}
	}
	return false
}

func secureEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

package main

import (
	"crypto/subtle"
	"log"
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
		if cfg.LogProxyRequests {
			log.Printf("proxy request auth bypass request_id=%s connection=%s remote_ip=%s", requestID, connectionID, remoteIP)
		}
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

	if !enforceNonceReplayProtection(w, headers, identity.Namespace, connectionID, remoteIP, requestID, nonceCache, cfg) {
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
		if cfg.LogProxyRequests {
			log.Printf("proxy request header validation failed request_id=%s connection=%s remote_ip=%s err=%v", requestID, connectionID, remoteIP, err)
		}
		writeProxyAuthFailure(w)
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
		if cfg.LogProxyRequests {
			log.Printf("proxy request component validation failed request_id=%s connection=%s remote_ip=%s err=%v", requestID, connectionID, remoteIP, componentErr)
		}
		writeProxyAuthFailure(w)
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
		if cfg.LogProxyRequests {
			log.Printf("proxy request identity extraction failed request_id=%s connection=%s remote_ip=%s err=%v", requestID, connectionID, remoteIP, identityErr)
		}
		writeProxyAuthFailure(w)
		return authorizedIdentity{}, false
	}
	if cfg.LogProxyRequests {
		log.Printf("proxy request subject resolved request_id=%s connection=%s namespace=%s subject=%s", requestID, connectionID, namespace, subject)
	}
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
	connectionID string,
	remoteIP string,
	requestID string,
	nonceCache *nonceReplayCache,
	cfg config.Config,
) bool {
	nonce, nonceErr := extractSignatureNonce(headers.Get(headerSignatureInput))
	if nonceErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request nonce extraction failed request_id=%s connection=%s remote_ip=%s err=%v", requestID, connectionID, remoteIP, nonceErr)
		}
		writeProxyAuthFailure(w)
		return false
	}
	if nonceCache != nil && nonceCache.Seen(namespace, nonce, time.Now().UTC()) {
		if cfg.LogProxyRequests {
			log.Printf("proxy request replay detected request_id=%s connection=%s remote_ip=%s namespace=%s", requestID, connectionID, remoteIP, namespace)
		}
		writeProxyAuthFailure(w)
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
		writeProxyAuthFailure(w)
		return false
	}

	approved, claimErr := claimsCache.IsApproved(r.Context(), connectionID, identity.Namespace, identity.PublicKey)
	if claimErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request claim cache failed request_id=%s connection=%s remote_ip=%s err=%v", requestID, connectionID, remoteIP, claimErr)
		}
		writeProxyAuthFailure(w)
		return false
	}

	if cfg.LogProxyRequests {
		log.Printf("proxy claim cache precheck request_id=%s connection=%s namespace=%s approved=%t", requestID, connectionID, identity.Namespace, approved)
	}
	if !approved {
		claimAttempt := claimRegistrationAttempt{
			Enabled: cfg.AutoRegisterClaims,
		}
		if cfg.AutoRegisterClaims {
			submitResult, submitErr := claimsCache.SubmitClaim(r.Context(), claimcache.SubmitClaimInput{
				Service:   connectionID,
				Namespace: identity.Namespace,
				PublicKey: identity.PublicKey,
				AgentIP:   remoteIP,
				Subject:   identity.Subject,
			})
			claimAttempt.Result = submitResult
			claimAttempt.Err = submitErr
			if cfg.LogProxyRequests {
				if submitErr != nil {
					log.Printf(
						"proxy claim submit failed request_id=%s connection=%s namespace=%s subject=%s remote_ip=%s err=%v",
						requestID,
						connectionID,
						identity.Namespace,
						identity.Subject,
						remoteIP,
						submitErr,
					)
				} else {
					log.Printf(
						"proxy claim submit result request_id=%s connection=%s namespace=%s subject=%s remote_ip=%s claim_id=%s status=%s http_status=%d code=%s",
						requestID,
						connectionID,
						identity.Namespace,
						identity.Subject,
						remoteIP,
						submitResult.ClaimID,
						submitResult.Status,
						submitResult.HTTPStatus,
						submitResult.Code,
					)
				}
			}
		}
		if cfg.LogProxyRequests {
			log.Printf("proxy request denied by claim cache request_id=%s connection=%s remote_ip=%s namespace=%s", requestID, connectionID, remoteIP, identity.Namespace)
		}
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
			if cfg.LogProxyRequests {
				log.Printf(
					"admin request denied request_id=%s mode=%s reason=token_not_configured path=%s method=%s remote_ip=%s",
					requestID,
					mode,
					r.URL.Path,
					r.Method,
					remoteIP,
				)
			}
			writeJSON(w, http.StatusInternalServerError, errorResponse{
				Error: "admin token mode requires GATEWAY_ADMIN_TOKEN",
				Code:  "ADMIN_TOKEN_NOT_CONFIGURED",
			})
			return false
		}
		if hasAdminToken(r, adminToken) {
			if cfg.LogProxyRequests {
				log.Printf(
					"admin request access granted request_id=%s via token mode=%s path=%s method=%s",
					requestID,
					mode,
					r.URL.Path,
					r.Method,
				)
			}
			return true
		}
		if cfg.LogProxyRequests {
			log.Printf(
				"admin request denied request_id=%s mode=%s reason=token_required path=%s method=%s remote_ip=%s",
				requestID,
				mode,
				r.URL.Path,
				r.Method,
				remoteIP,
			)
		}
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: "admin endpoints require a valid admin token",
			Code:  "ADMIN_TOKEN_REQUIRED",
		})
		return false
	case config.AdminAccessModeLoopback:
		if isLoopbackClient(remoteIP) {
			if cfg.LogProxyRequests {
				log.Printf(
					"admin request access granted request_id=%s via loopback mode=%s path=%s method=%s remote_ip=%s",
					requestID,
					mode,
					r.URL.Path,
					r.Method,
					remoteIP,
				)
			}
			return true
		}
		if cfg.LogProxyRequests {
			log.Printf(
				"admin request denied request_id=%s mode=%s reason=loopback_required path=%s method=%s remote_ip=%s",
				requestID,
				mode,
				r.URL.Path,
				r.Method,
				remoteIP,
			)
		}
		writeJSON(w, http.StatusForbidden, errorResponse{
			Error: "admin endpoints require loopback client access",
			Code:  "ADMIN_LOOPBACK_REQUIRED",
		})
		return false
	default:
		if adminToken != "" && hasAdminToken(r, adminToken) {
			if cfg.LogProxyRequests {
				log.Printf(
					"admin request access granted request_id=%s via token mode=%s path=%s method=%s",
					requestID,
					mode,
					r.URL.Path,
					r.Method,
				)
			}
			return true
		}
		if isLoopbackClient(remoteIP) {
			if cfg.LogProxyRequests {
				log.Printf(
					"admin request access granted request_id=%s via loopback mode=%s path=%s method=%s remote_ip=%s",
					requestID,
					mode,
					r.URL.Path,
					r.Method,
					remoteIP,
				)
			}
			return true
		}
		if cfg.LogProxyRequests {
			log.Printf(
				"admin request denied request_id=%s mode=%s reason=token_or_loopback_required path=%s method=%s remote_ip=%s",
				requestID,
				mode,
				r.URL.Path,
				r.Method,
				remoteIP,
			)
		}
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

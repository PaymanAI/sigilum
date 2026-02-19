package main

import (
	"log"
	"net/http"
	"time"

	"sigilum.local/gateway/config"
	claimcache "sigilum.local/gateway/internal/claims"
	"sigilum.local/sdk-go/sigilum"
)

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
	if shouldBypassConnectionAuthorization(cfg, connectionID) {
		if cfg.LogProxyRequests {
			log.Printf("proxy request auth bypass enabled connection=%s remote_ip=%s", connectionID, remoteIP)
		}
		return authorizedIdentity{}, true
	}

	headers := r.Header.Clone()
	if !verifySignedRequest(w, r, headers, body, connectionID, remoteIP, cfg) {
		return authorizedIdentity{}, false
	}

	identity, ok := resolveAuthorizedIdentity(w, headers, connectionID, remoteIP, cfg)
	if !ok {
		return authorizedIdentity{}, false
	}

	if !enforceNonceReplayProtection(w, headers, identity.Namespace, connectionID, remoteIP, nonceCache, cfg) {
		return authorizedIdentity{}, false
	}

	if !enforceClaimAuthorization(w, r, claimsCache, connectionID, identity, remoteIP, cfg) {
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
	cfg config.Config,
) bool {
	if err := validateSigilumAuthHeaders(headers); err != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request header validation failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, err)
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
		writeVerificationFailure(w, signatureResult, cfg.LogProxyRequests, connectionID, remoteIP)
		return false
	}

	if componentErr := validateSignatureComponents(headers.Get(headerSignatureInput), len(body) > 0); componentErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request component validation failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, componentErr)
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
	cfg config.Config,
) (authorizedIdentity, bool) {
	namespace, publicKey, subject, identityErr := extractSigilumIdentity(headers)
	if identityErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request identity extraction failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, identityErr)
		}
		writeProxyAuthFailure(w)
		return authorizedIdentity{}, false
	}
	if cfg.LogProxyRequests {
		log.Printf("proxy request subject resolved connection=%s namespace=%s subject=%s", connectionID, namespace, subject)
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
	nonceCache *nonceReplayCache,
	cfg config.Config,
) bool {
	nonce, nonceErr := extractSignatureNonce(headers.Get(headerSignatureInput))
	if nonceErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request nonce extraction failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, nonceErr)
		}
		writeProxyAuthFailure(w)
		return false
	}
	if nonceCache != nil && nonceCache.Seen(namespace, nonce, time.Now().UTC()) {
		if cfg.LogProxyRequests {
			log.Printf("proxy request replay detected connection=%s remote_ip=%s namespace=%s", connectionID, remoteIP, namespace)
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
	cfg config.Config,
) bool {
	if claimsCache == nil {
		writeProxyAuthFailure(w)
		return false
	}

	approved, claimErr := claimsCache.IsApproved(r.Context(), connectionID, identity.Namespace, identity.PublicKey)
	if claimErr != nil {
		if cfg.LogProxyRequests {
			log.Printf("proxy request claim cache failed connection=%s remote_ip=%s err=%v", connectionID, remoteIP, claimErr)
		}
		writeProxyAuthFailure(w)
		return false
	}

	if cfg.LogProxyRequests {
		log.Printf("proxy claim cache precheck connection=%s namespace=%s approved=%t", connectionID, identity.Namespace, approved)
	}
	if !approved {
		if cfg.LogProxyRequests {
			log.Printf("proxy request denied by claim cache connection=%s remote_ip=%s namespace=%s", connectionID, remoteIP, identity.Namespace)
		}
		writeProxyAuthFailure(w)
		return false
	}
	return true
}

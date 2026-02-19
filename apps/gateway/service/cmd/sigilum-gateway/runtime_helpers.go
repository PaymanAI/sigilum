package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
	"sigilum.local/sdk-go/sigilum"
)

func evaluateRotationPolicy(conn connectors.Connection, mode string, gracePeriod time.Duration, now time.Time) (bool, string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "off" {
		return false, ""
	}

	dueAt := conn.NextRotationDueAt
	if dueAt.IsZero() {
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

func writeVerificationFailure(
	w http.ResponseWriter,
	result sigilum.VerifySignatureResult,
	logEnabled bool,
	connectionID string,
	remoteIP string,
	requestID string,
) {
	if logEnabled {
		log.Printf("proxy request verify failed request_id=%s connection=%s remote_ip=%s reason=%s", requestID, connectionID, remoteIP, result.Reason)
	}
	writeProxyAuthFailure(w)
}

func shouldAutoDiscoverMCPTools(conn connectors.Connection) bool {
	if len(conn.MCPDiscovery.Tools) > 0 {
		return false
	}
	return conn.MCPDiscovery.LastDiscoveredAt.IsZero()
}

func hasSigilumHeaders(headers http.Header) bool {
	return strings.TrimSpace(headers.Get(headerSignatureInput)) != "" ||
		strings.TrimSpace(headers.Get(headerSignature)) != "" ||
		strings.TrimSpace(headers.Get(headerNamespace)) != "" ||
		strings.TrimSpace(headers.Get(headerSubject)) != "" ||
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

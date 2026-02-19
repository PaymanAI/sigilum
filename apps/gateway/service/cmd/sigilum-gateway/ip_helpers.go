package main

import (
	"net"
	"net/http"
	"strings"
)

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

func isLoopbackClient(remoteIP string) bool {
	trimmed := strings.TrimSpace(remoteIP)
	if trimmed == "" {
		return false
	}
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.IsLoopback()
	}
	return false
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

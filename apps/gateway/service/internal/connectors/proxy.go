package connectors

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func NewReverseProxy(cfg ProxyConfig, upstreamPath string, rawQuery string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(cfg.Connection.BaseURL)
	if err != nil {
		return nil, err
	}

	joinedPath := joinURLPath(target.Path, cfg.Connection.PathPrefix, upstreamPath)

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = joinedPath
		req.URL.RawPath = joinedPath
		req.URL.RawQuery = rawQuery

		stripSigilumHeaders(req.Header)
		query := req.URL.Query()
		ApplyAuthQuery(query, cfg.Connection, cfg.Secret)
		req.URL.RawQuery = query.Encode()
		ApplyAuthHeader(req.Header, cfg.Connection, cfg.Secret)
	}

	return proxy, nil
}

func joinURLPath(paths ...string) string {
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

func stripSigilumHeaders(headers http.Header) {
	headers.Del("Signature-Input")
	headers.Del("Signature")
	headers.Del("Content-Digest")
	headers.Del("Sigilum-Namespace")
	headers.Del("Sigilum-Subject")
	headers.Del("Sigilum-Agent-Key")
	headers.Del("Sigilum-Agent-Cert")
}

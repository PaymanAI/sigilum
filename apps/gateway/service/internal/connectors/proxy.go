package connectors

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"sigilum.local/gateway/internal/util"
)

func NewReverseProxy(cfg ProxyConfig, upstreamPath string, rawQuery string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(cfg.Connection.BaseURL)
	if err != nil {
		return nil, err
	}

	joinedPath := util.JoinPath(target.Path, cfg.Connection.PathPrefix, upstreamPath)

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

func stripSigilumHeaders(headers http.Header) {
	headers.Del("Signature-Input")
	headers.Del("Signature")
	headers.Del("Content-Digest")
	headers.Del("Sigilum-Namespace")
	headers.Del("Sigilum-Subject")
	headers.Del("Sigilum-Agent-Key")
	headers.Del("Sigilum-Agent-Cert")
}

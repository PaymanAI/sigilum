package sigilum

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertifyRequestSignsNamespaceURL(t *testing.T) {
	tmp := t.TempDir()
	_, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("init identity: %v", err)
	}

	var capturedURL string
	var capturedMethod string
	var capturedHeaders map[string]string
	var capturedBody []byte

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = srv.URL + r.URL.String()
		capturedMethod = r.Method
		capturedBody, _ = io.ReadAll(r.Body)
		capturedHeaders = map[string]string{}
		for key, values := range r.Header {
			if len(values) > 0 {
				capturedHeaders[key] = values[0]
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	bindings, err := Certify(CertifyOptions{
		Namespace:  "alice",
		HomeDir:    tmp,
		APIBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("certify: %v", err)
	}

	resp, err := bindings.Request(
		context.Background(),
		"/claims",
		http.MethodGet,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", resp.StatusCode)
	}

	if capturedURL != srv.URL+"/v1/namespaces/alice/claims" {
		t.Fatalf("unexpected request url: %s", capturedURL)
	}

	normalizedHeaders := map[string]string{}
	for key, value := range capturedHeaders {
		normalizedHeaders[key] = value
	}

	verify := VerifyHTTPSignature(VerifySignatureInput{
		URL:               capturedURL,
		Method:            capturedMethod,
		Headers:           normalizedHeaders,
		Body:              capturedBody,
		ExpectedNamespace: "alice",
	})
	if !verify.Valid {
		t.Fatalf("expected valid signature, got reason: %s", verify.Reason)
	}
}

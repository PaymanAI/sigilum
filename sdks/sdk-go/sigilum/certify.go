package sigilum

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const defaultAPIBaseURL = "https://api.sigilum.id"

type SigilumBindings struct {
	identity    SigilumIdentity
	APIBaseURL  string
	HTTPClient  *http.Client
	Namespace   string
	DID         string
	KeyID       string
	PublicKey   string
	Certificate SigilumCertificate
}

func resolveAPIBaseURL(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if env := strings.TrimSpace(os.Getenv("SIGILUM_API_URL")); env != "" {
		return env
	}
	return defaultAPIBaseURL
}

func resolveURL(value, base string) string {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(value, "/")
}

func Certify(options CertifyOptions) (*SigilumBindings, error) {
	identity, err := LoadIdentity(LoadIdentityOptions{
		Namespace: options.Namespace,
		HomeDir:   options.HomeDir,
	})
	if err != nil {
		return nil, err
	}

	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	apiBaseURL := resolveAPIBaseURL(options.APIBaseURL)

	return &SigilumBindings{
		identity:    identity,
		APIBaseURL:  apiBaseURL,
		HTTPClient:  client,
		Namespace:   identity.Namespace,
		DID:         identity.DID,
		KeyID:       identity.KeyID,
		PublicKey:   identity.PublicKey,
		Certificate: identity.Certificate,
	}, nil
}

func (b *SigilumBindings) Sign(input SignRequestInput) (SignedRequest, error) {
	if b == nil {
		return SignedRequest{}, fmt.Errorf("nil SigilumBindings")
	}
	input.URL = resolveURL(input.URL, b.APIBaseURL)
	return SignHTTPRequest(b.identity, input)
}

func (b *SigilumBindings) Do(ctx context.Context, input SignRequestInput) (*http.Response, error) {
	signed, err := b.Sign(input)
	if err != nil {
		return nil, err
	}

	var bodyReader *bytes.Reader
	if len(signed.Body) > 0 {
		bodyReader = bytes.NewReader(signed.Body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, signed.Method, signed.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	for key, value := range signed.Headers {
		req.Header.Set(key, value)
	}

	return b.HTTPClient.Do(req)
}

func (b *SigilumBindings) Request(
	ctx context.Context,
	path string,
	method string,
	headers map[string]string,
	body []byte,
) (*http.Response, error) {
	namespaceBase := GetNamespaceAPIBase(b.APIBaseURL, b.identity.Namespace)
	url := resolveURL(path, namespaceBase)
	return b.Do(ctx, SignRequestInput{
		URL:     url,
		Method:  method,
		Headers: headers,
		Body:    body,
	})
}

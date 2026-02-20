package sigilum

import "net/http"

type SigilumCertificateProof struct {
	Alg string `json:"alg"`
	Sig string `json:"sig"`
}

type SigilumCertificate struct {
	Version   int                     `json:"version"`
	Namespace string                  `json:"namespace"`
	DID       string                  `json:"did"`
	KeyID     string                  `json:"keyId"`
	PublicKey string                  `json:"publicKey"`
	IssuedAt  string                  `json:"issuedAt"`
	ExpiresAt *string                 `json:"expiresAt"`
	Proof     SigilumCertificateProof `json:"proof"`
}

type SigilumIdentity struct {
	Namespace    string
	DID          string
	KeyID        string
	PublicKey    string
	PrivateKey   []byte
	Certificate  SigilumCertificate
	HomeDir      string
	IdentityPath string
}

type InitIdentityOptions struct {
	Namespace string
	HomeDir   string
	Force     bool
}

type InitIdentityResult struct {
	Namespace    string
	DID          string
	KeyID        string
	PublicKey    string
	Created      bool
	HomeDir      string
	IdentityPath string
}

type LoadIdentityOptions struct {
	Namespace string
	HomeDir   string
}

type SignRequestInput struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    []byte
	Created int64
	Nonce   string
	Subject string
}

type SignedRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    []byte
}

type VerifySignatureInput struct {
	URL               string
	Method            string
	Headers           map[string]string
	Body              []byte
	ExpectedNamespace string
	ExpectedSubject   string
	NowUnix           int64
	MaxAgeSeconds     int64
	SeenNonces        map[string]struct{}
}

type VerifySignatureResult struct {
	Valid     bool
	Code      string
	Namespace string
	Subject   string
	KeyID     string
	Reason    string
}

type CertifyOptions struct {
	Namespace  string
	HomeDir    string
	APIBaseURL string
	HTTPClient *http.Client
}

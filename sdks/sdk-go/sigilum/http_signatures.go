package sigilum

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var signatureInputPattern = regexp.MustCompile(`^sig1=\(([^)]*)\);created=(\d+);keyid="([^"]+)";alg="([^"]+)";nonce="([^"]+)"$`)
var signaturePattern = regexp.MustCompile(`^sig1=:([^:]+):$`)

type parsedSignatureInput struct {
	Components []string
	Created    int64
	KeyID      string
	Alg        string
	Nonce      string
}

func normalizeHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range headers {
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return out
}

func normalizeMethod(method string) string {
	if strings.TrimSpace(method) == "" {
		return "GET"
	}
	return strings.ToUpper(strings.TrimSpace(method))
}

func contentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func signatureParams(components []string, created int64, keyID, nonce string) string {
	quoted := make([]string, 0, len(components))
	for _, component := range components {
		quoted = append(quoted, "\""+component+"\"")
	}
	return "(" + strings.Join(quoted, " ") + ");created=" +
		strconv.FormatInt(created, 10) +
		";keyid=\"" + keyID + "\";alg=\"ed25519\";nonce=\"" + nonce + "\""
}

func normalizeTargetURI(raw string) string {
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	return parsed.String()
}

func componentValue(component string, method string, url string, headers map[string]string) (string, error) {
	switch component {
	case "@method":
		return strings.ToLower(method), nil
	case "@target-uri":
		return normalizeTargetURI(url), nil
	default:
		value, ok := headers[component]
		if !ok || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("missing required signed header: %s", component)
		}
		return value, nil
	}
}

func signingBase(components []string, method string, url string, headers map[string]string, sigParams string) ([]byte, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		value, err := componentValue(component, method, url, headers)
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("\"%s\": %s", component, value))
	}
	lines = append(lines, fmt.Sprintf("\"@signature-params\": %s", sigParams))
	return []byte(strings.Join(lines, "\n")), nil
}

func EncodeCertificateHeader(certificate SigilumCertificate) (string, error) {
	bytes, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func DecodeCertificateHeader(value string) (SigilumCertificate, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return SigilumCertificate{}, err
	}
	var certificate SigilumCertificate
	if err := json.Unmarshal(bytes, &certificate); err != nil {
		return SigilumCertificate{}, err
	}
	return certificate, nil
}

func parseSignatureInputHeader(value string) (parsedSignatureInput, error) {
	match := signatureInputPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 6 {
		return parsedSignatureInput{}, fmt.Errorf("invalid Signature-Input header format")
	}
	componentsRaw := match[1]
	createdRaw := match[2]
	keyID := match[3]
	alg := match[4]
	nonce := match[5]

	created, err := strconv.ParseInt(createdRaw, 10, 64)
	if err != nil {
		return parsedSignatureInput{}, fmt.Errorf("invalid created timestamp in Signature-Input")
	}

	parts := strings.Fields(strings.TrimSpace(componentsRaw))
	components := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) < 2 || !strings.HasPrefix(part, "\"") || !strings.HasSuffix(part, "\"") {
			return parsedSignatureInput{}, fmt.Errorf("invalid component in Signature-Input: %s", part)
		}
		components = append(components, strings.TrimSuffix(strings.TrimPrefix(part, "\""), "\""))
	}

	return parsedSignatureInput{
		Components: components,
		Created:    created,
		KeyID:      keyID,
		Alg:        alg,
		Nonce:      nonce,
	}, nil
}

func parseSignatureHeader(value string) ([]byte, error) {
	match := signaturePattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 2 {
		return nil, fmt.Errorf("invalid Signature header format")
	}
	return base64.StdEncoding.DecodeString(match[1])
}

func SignHTTPRequest(identity SigilumIdentity, input SignRequestInput) (SignedRequest, error) {
	if strings.TrimSpace(input.URL) == "" {
		return SignedRequest{}, fmt.Errorf("request URL is required")
	}
	method := normalizeMethod(input.Method)
	normalizedURL := normalizeTargetURI(input.URL)
	headers := normalizeHeaders(input.Headers)
	body := input.Body

	if len(body) > 0 {
		headers["content-digest"] = contentDigest(body)
	}

	certHeader, err := EncodeCertificateHeader(identity.Certificate)
	if err != nil {
		return SignedRequest{}, err
	}

	headers["sigilum-namespace"] = identity.Namespace
	headers["sigilum-agent-key"] = identity.PublicKey
	headers["sigilum-agent-cert"] = certHeader

	components := []string{"@method", "@target-uri", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"}
	if len(body) > 0 {
		components = []string{"@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-agent-key", "sigilum-agent-cert"}
	}

	created := input.Created
	if created <= 0 {
		created = time.Now().Unix()
	}
	nonce := strings.TrimSpace(input.Nonce)
	if nonce == "" {
		nonce, err = randomUUIDV4()
		if err != nil {
			return SignedRequest{}, err
		}
	}
	sigParams := signatureParams(components, created, identity.KeyID, nonce)
	base, err := signingBase(components, method, normalizedURL, headers, sigParams)
	if err != nil {
		return SignedRequest{}, err
	}

	private := ed25519.NewKeyFromSeed(identity.PrivateKey)
	signature := ed25519.Sign(private, base)

	headers["signature-input"] = "sig1=" + sigParams
	headers["signature"] = "sig1=:" + base64.StdEncoding.EncodeToString(signature) + ":"

	return SignedRequest{
		URL:     normalizedURL,
		Method:  method,
		Headers: headers,
		Body:    body,
	}, nil
}

func VerifyHTTPSignature(input VerifySignatureInput) VerifySignatureResult {
	headers := normalizeHeaders(input.Headers)
	signatureInput := headers["signature-input"]
	signatureValue := headers["signature"]

	if signatureInput == "" || signatureValue == "" {
		return VerifySignatureResult{Valid: false, Reason: "Missing Signature-Input or Signature header"}
	}

	parsed, err := parseSignatureInputHeader(signatureInput)
	if err != nil {
		return VerifySignatureResult{Valid: false, Reason: err.Error()}
	}
	if strings.ToLower(parsed.Alg) != "ed25519" {
		return VerifySignatureResult{Valid: false, Reason: "Unsupported signature algorithm"}
	}
	if parsed.Created <= 0 {
		return VerifySignatureResult{Valid: false, Reason: "Invalid Signature-Input created timestamp"}
	}
	if input.MaxAgeSeconds > 0 {
		now := input.NowUnix
		if now <= 0 {
			now = time.Now().Unix()
		}
		age := now - parsed.Created
		if age < 0 || age > input.MaxAgeSeconds {
			return VerifySignatureResult{Valid: false, Reason: "Signature expired or not yet valid"}
		}
	}
	if input.SeenNonces != nil {
		if _, exists := input.SeenNonces[parsed.Nonce]; exists {
			return VerifySignatureResult{Valid: false, Reason: "Replay detected: nonce already seen"}
		}
		input.SeenNonces[parsed.Nonce] = struct{}{}
	}

	signature, err := parseSignatureHeader(signatureValue)
	if err != nil {
		return VerifySignatureResult{Valid: false, Reason: err.Error()}
	}

	certHeader := headers["sigilum-agent-cert"]
	if certHeader == "" {
		return VerifySignatureResult{Valid: false, Reason: "Missing sigilum-agent-cert header"}
	}
	certificate, err := DecodeCertificateHeader(certHeader)
	if err != nil {
		return VerifySignatureResult{Valid: false, Reason: "Invalid sigilum-agent-cert header"}
	}
	if !VerifyCertificate(certificate) {
		return VerifySignatureResult{Valid: false, Reason: "Invalid agent certificate"}
	}

	namespaceHeader := headers["sigilum-namespace"]
	if namespaceHeader == "" || namespaceHeader != certificate.Namespace {
		return VerifySignatureResult{Valid: false, Reason: "Namespace header mismatch"}
	}
	if strings.TrimSpace(input.ExpectedNamespace) != "" && input.ExpectedNamespace != namespaceHeader {
		return VerifySignatureResult{Valid: false, Reason: fmt.Sprintf("Namespace mismatch: expected %s, got %s", input.ExpectedNamespace, namespaceHeader)}
	}

	keyHeader := headers["sigilum-agent-key"]
	if keyHeader == "" {
		return VerifySignatureResult{Valid: false, Reason: "Missing sigilum-agent-key header"}
	}
	if keyHeader != certificate.PublicKey {
		return VerifySignatureResult{Valid: false, Reason: "Certificate public key mismatch"}
	}
	if parsed.KeyID != certificate.KeyID {
		return VerifySignatureResult{Valid: false, Reason: "keyid mismatch"}
	}

	if len(input.Body) > 0 {
		expectedDigest := contentDigest(input.Body)
		if headers["content-digest"] != expectedDigest {
			return VerifySignatureResult{Valid: false, Reason: "Content digest mismatch"}
		}
	}

	sigParams := signatureParams(parsed.Components, parsed.Created, parsed.KeyID, parsed.Nonce)
	base, err := signingBase(parsed.Components, normalizeMethod(input.Method), normalizeTargetURI(input.URL), headers, sigParams)
	if err != nil {
		return VerifySignatureResult{Valid: false, Reason: err.Error()}
	}

	publicKey, err := publicKeyFromEncoded(keyHeader)
	if err != nil {
		return VerifySignatureResult{Valid: false, Reason: "Invalid sigilum-agent-key header"}
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), base, signature) {
		return VerifySignatureResult{Valid: false, Reason: "Signature verification failed"}
	}

	return VerifySignatureResult{Valid: true, Namespace: certificate.Namespace, KeyID: certificate.KeyID}
}

func randomUUIDV4() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(buffer)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}

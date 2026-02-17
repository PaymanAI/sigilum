package sigilum

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	identityRecordVersion = 1
	certificateVersion    = 1
	identitiesDirName     = "identities"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

func DefaultSigilumHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sigilum"
	}
	return filepath.Join(home, ".sigilum")
}

func normalizeNamespace(raw string) (string, error) {
	namespace := strings.ToLower(strings.TrimSpace(raw))
	if namespace == "" {
		return "", errors.New("namespace is required")
	}
	if !namespacePattern.MatchString(namespace) {
		return "", errors.New("namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ (3-64 chars, lowercase)")
	}
	return namespace, nil
}

func getHomeDir(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if env := os.Getenv("SIGILUM_HOME"); strings.TrimSpace(env) != "" {
		return env
	}
	return DefaultSigilumHome()
}

func identityDir(homeDir, namespace string) string {
	return filepath.Join(homeDir, identitiesDirName, namespace)
}

func identityPath(homeDir, namespace string) string {
	return filepath.Join(identityDir(homeDir, namespace), "identity.json")
}

func makeDID(namespace string) string {
	return "did:sigilum:" + namespace
}

func fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

func makeKeyID(did string, publicKey []byte) string {
	return did + "#ed25519-" + fingerprint(publicKey)
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func certificatePayload(cert SigilumCertificate) []byte {
	expiresAt := ""
	if cert.ExpiresAt != nil {
		expiresAt = *cert.ExpiresAt
	}
	payload := []string{
		"sigilum-certificate-v1",
		"namespace:" + cert.Namespace,
		"did:" + cert.DID,
		"key-id:" + cert.KeyID,
		"public-key:" + cert.PublicKey,
		"issued-at:" + cert.IssuedAt,
		"expires-at:" + expiresAt,
	}
	return []byte(strings.Join(payload, "\n"))
}

func toBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func fromBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func publicKeyFromEncoded(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, "ed25519:") {
		return nil, fmt.Errorf("unsupported public key format: %s", encoded)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, "ed25519:"))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(decoded))
	}
	return decoded, nil
}

func VerifyCertificate(cert SigilumCertificate) bool {
	if cert.Version != certificateVersion {
		return false
	}
	if cert.Proof.Alg != "ed25519" {
		return false
	}
	publicKey, err := publicKeyFromEncoded(cert.PublicKey)
	if err != nil {
		return false
	}
	signature, err := fromBase64URL(cert.Proof.Sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), certificatePayload(cert), signature)
}

type identityRecord struct {
	Version     int               `json:"version"`
	Namespace   string            `json:"namespace"`
	DID         string            `json:"did"`
	KeyID       string            `json:"keyId"`
	PublicKey   string            `json:"publicKey"`
	PrivateKey  string            `json:"privateKey"`
	Certificate SigilumCertificate `json:"certificate"`
	CreatedAt   string            `json:"createdAt"`
	UpdatedAt   string            `json:"updatedAt"`
}

func createIdentityRecord(namespace string) (*identityRecord, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := privateKey.Seed()
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	did := makeDID(namespace)
	keyID := makeKeyID(did, publicKey)
	now := nowISO()

	cert := SigilumCertificate{
		Version:   certificateVersion,
		Namespace: namespace,
		DID:       did,
		KeyID:     keyID,
		PublicKey: "ed25519:" + publicKeyBase64,
		IssuedAt:  now,
		ExpiresAt: nil,
		Proof: SigilumCertificateProof{
			Alg: "ed25519",
			Sig: "",
		},
	}

	signature := ed25519.Sign(privateKey, certificatePayload(cert))
	cert.Proof.Sig = toBase64URL(signature)

	return &identityRecord{
		Version:     identityRecordVersion,
		Namespace:   namespace,
		DID:         did,
		KeyID:       keyID,
		PublicKey:   "ed25519:" + publicKeyBase64,
		PrivateKey:  base64.StdEncoding.EncodeToString(seed),
		Certificate: cert,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func writeIdentityRecord(homeDir, namespace string, record *identityRecord) (string, error) {
	dir := identityDir(homeDir, namespace)
	path := identityPath(homeDir, namespace)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	bytes, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	bytes = append(bytes, '\n')

	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func readIdentityRecord(path string) (*identityRecord, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var record identityRecord
	if err := json.Unmarshal(bytes, &record); err != nil {
		return nil, fmt.Errorf("failed to parse identity file %s: %w", path, err)
	}
	if record.Version != identityRecordVersion {
		return nil, fmt.Errorf("unsupported identity version: %d", record.Version)
	}
	if record.Namespace == "" || record.DID == "" || record.KeyID == "" || record.PublicKey == "" || record.PrivateKey == "" {
		return nil, fmt.Errorf("identity file %s is missing required fields", path)
	}
	return &record, nil
}

func ListNamespaces(explicitHomeDir string) ([]string, error) {
	home := getHomeDir(explicitHomeDir)
	root := filepath.Join(home, identitiesDirName)

	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	namespaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		identity := filepath.Join(root, entry.Name(), "identity.json")
		if _, err := os.Stat(identity); err == nil {
			namespaces = append(namespaces, entry.Name())
		}
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

func resolveNamespace(explicitNamespace, explicitHomeDir string) (string, error) {
	if strings.TrimSpace(explicitNamespace) != "" {
		return normalizeNamespace(explicitNamespace)
	}
	if env := strings.TrimSpace(os.Getenv("SIGILUM_NAMESPACE")); env != "" {
		return normalizeNamespace(env)
	}

	namespaces, err := ListNamespaces(explicitHomeDir)
	if err != nil {
		return "", err
	}
	if len(namespaces) == 1 {
		return namespaces[0], nil
	}
	if len(namespaces) == 0 {
		return "", errors.New("no Sigilum identity found. Run `sigilum init <namespace>` first")
	}
	return "", fmt.Errorf("multiple identities found (%s). Pass namespace explicitly or set SIGILUM_NAMESPACE", strings.Join(namespaces, ", "))
}

func LoadIdentity(options LoadIdentityOptions) (SigilumIdentity, error) {
	home := getHomeDir(options.HomeDir)
	namespace, err := resolveNamespace(options.Namespace, home)
	if err != nil {
		return SigilumIdentity{}, err
	}

	path := identityPath(home, namespace)
	record, err := readIdentityRecord(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SigilumIdentity{}, fmt.Errorf("Sigilum identity not found for namespace %q at %s. Run `sigilum init %s` first", namespace, path, namespace)
		}
		return SigilumIdentity{}, err
	}

	seed, err := base64.StdEncoding.DecodeString(record.PrivateKey)
	if err != nil {
		return SigilumIdentity{}, fmt.Errorf("invalid private key encoding: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return SigilumIdentity{}, fmt.Errorf("invalid private key length: %d", len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	expectedPublic := "ed25519:" + base64.StdEncoding.EncodeToString(publicKey)
	if expectedPublic != record.PublicKey {
		return SigilumIdentity{}, errors.New("public key mismatch in identity file")
	}

	if !VerifyCertificate(record.Certificate) {
		return SigilumIdentity{}, errors.New("identity certificate verification failed")
	}
	if record.Certificate.Namespace != namespace ||
		record.Certificate.DID != record.DID ||
		record.Certificate.KeyID != record.KeyID ||
		record.Certificate.PublicKey != record.PublicKey {
		return SigilumIdentity{}, errors.New("certificate and identity record do not match")
	}

	return SigilumIdentity{
		Namespace:    namespace,
		DID:          record.DID,
		KeyID:        record.KeyID,
		PublicKey:    record.PublicKey,
		PrivateKey:   seed,
		Certificate:  record.Certificate,
		HomeDir:      home,
		IdentityPath: path,
	}, nil
}

func InitIdentity(options InitIdentityOptions) (InitIdentityResult, error) {
	namespace, err := normalizeNamespace(options.Namespace)
	if err != nil {
		return InitIdentityResult{}, err
	}
	home := getHomeDir(options.HomeDir)
	path := identityPath(home, namespace)

	if _, err := os.Stat(path); err == nil && !options.Force {
		identity, err := LoadIdentity(LoadIdentityOptions{Namespace: namespace, HomeDir: home})
		if err != nil {
			return InitIdentityResult{}, err
		}
		return InitIdentityResult{
			Namespace:    identity.Namespace,
			DID:          identity.DID,
			KeyID:        identity.KeyID,
			PublicKey:    identity.PublicKey,
			Created:      false,
			HomeDir:      home,
			IdentityPath: path,
		}, nil
	}

	record, err := createIdentityRecord(namespace)
	if err != nil {
		return InitIdentityResult{}, err
	}
	finalPath, err := writeIdentityRecord(home, namespace, record)
	if err != nil {
		return InitIdentityResult{}, err
	}

	return InitIdentityResult{
		Namespace:    namespace,
		DID:          record.DID,
		KeyID:        record.KeyID,
		PublicKey:    record.PublicKey,
		Created:      true,
		HomeDir:      home,
		IdentityPath: finalPath,
	}, nil
}

func GetNamespaceAPIBase(apiBaseURL, namespace string) string {
	base := strings.TrimRight(apiBaseURL, "/")
	return base + "/v1/namespaces/" + url.PathEscape(namespace)
}

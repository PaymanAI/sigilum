package connectors

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyConnectionPrefix = "conn/"
)

var (
	ErrConnectionNotFound = errors.New("connection not found")
	ErrConnectionExists   = errors.New("connection already exists")
)

type encryptedSecret struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Service struct {
	db   *badger.DB
	aead cipherAead
}

type cipherAead interface {
	NonceSize() int
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}

func NewService(dataDir string, masterKey string) (*Service, error) {
	if strings.TrimSpace(masterKey) == "" {
		return nil, errors.New("GATEWAY_MASTER_KEY is required")
	}

	opts := badger.DefaultOptions(path.Join(dataDir, "badger"))
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger: %w", err)
	}

	derived := sha256.Sum256([]byte(masterKey))
	aead, err := chacha20poly1305.NewX(derived[:])
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	return &Service{
		db:   db,
		aead: aead,
	}, nil
}

func (s *Service) Close() error {
	return s.db.Close()
}

func (s *Service) CreateConnection(input CreateConnectionInput) (Connection, error) {
	record, secrets, err := normalizeCreateInput(input)
	if err != nil {
		return Connection{}, err
	}

	secretPayload, err := marshalSecretsPayload(secrets)
	if err != nil {
		return Connection{}, err
	}

	secretBlob, err := s.encryptSecret(record.ID, 1, secretPayload)
	if err != nil {
		return Connection{}, err
	}

	err = s.db.Update(func(txn *badger.Txn) error {
		if _, err := txn.Get(metaKey(record.ID)); err == nil {
			return ErrConnectionExists
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		metaBytes, err := json.Marshal(record)
		if err != nil {
			return err
		}
		secretBytes, err := json.Marshal(secretBlob)
		if err != nil {
			return err
		}

		if err := txn.Set(metaKey(record.ID), metaBytes); err != nil {
			return err
		}
		return txn.Set(secretKey(record.ID, record.SecretVersion), secretBytes)
	})
	if err != nil {
		return Connection{}, err
	}

	return record, nil
}

func (s *Service) ListConnections() ([]Connection, error) {
	connections := make([]Connection, 0, 8)

	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte(keyConnectionPrefix)); it.ValidForPrefix([]byte(keyConnectionPrefix)); it.Next() {
			item := it.Item()
			key := string(item.Key())
			if !strings.HasSuffix(key, "/meta") {
				continue
			}

			err := item.Value(func(val []byte) error {
				var conn Connection
				if err := json.Unmarshal(val, &conn); err != nil {
					return err
				}
				connections = append(connections, conn)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(connections, func(i, j int) bool {
		return connections[i].ID < connections[j].ID
	})
	return connections, nil
}

func (s *Service) GetConnection(id string) (Connection, error) {
	var conn Connection
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(metaKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrConnectionNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &conn)
		})
	})
	if err != nil {
		return Connection{}, err
	}
	return conn, nil
}

func (s *Service) ResolveProxyConfig(id string) (ProxyConfig, error) {
	conn, err := s.GetConnection(id)
	if err != nil {
		return ProxyConfig{}, err
	}
	if conn.Status != ConnectionStatusActive {
		return ProxyConfig{}, fmt.Errorf("connection %q is %s", id, conn.Status)
	}

	secrets, err := s.getSecretVersionMap(conn.ID, conn.SecretVersion)
	if err != nil {
		return ProxyConfig{}, err
	}
	authSecretKey := strings.TrimSpace(conn.AuthSecretKey)
	if authSecretKey == "" {
		return ProxyConfig{}, fmt.Errorf("connection %q missing auth_secret_key", id)
	}
	secret, ok := secrets[authSecretKey]
	if !ok || strings.TrimSpace(secret) == "" {
		return ProxyConfig{}, fmt.Errorf("connection %q missing configured secret key %q", id, authSecretKey)
	}

	return ProxyConfig{
		Connection: conn,
		Secret:     secret,
		Secrets:    secrets,
	}, nil
}

func (s *Service) UpdateConnection(id string, input UpdateConnectionInput) (Connection, error) {
	var updated Connection

	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(metaKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrConnectionNotFound
		}
		if err != nil {
			return err
		}

		var conn Connection
		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &conn)
		}); err != nil {
			return err
		}

		if strings.TrimSpace(input.Name) != "" {
			conn.Name = strings.TrimSpace(input.Name)
		}
		if input.PathPrefix != "" {
			conn.PathPrefix = normalizePathPrefix(input.PathPrefix)
		}
		if strings.TrimSpace(input.AuthSecretKey) != "" {
			nextKey := strings.TrimSpace(input.AuthSecretKey)
			if len(conn.CredentialKeys) > 0 && !containsString(conn.CredentialKeys, nextKey) {
				return fmt.Errorf("auth_secret_key %q is not configured for connection", nextKey)
			}
			conn.AuthSecretKey = nextKey
		}
		if input.RotationIntervalDays > 0 {
			conn.RotationIntervalDays = input.RotationIntervalDays
			if conn.LastRotatedAt != "" {
				if ts, err := time.Parse(time.RFC3339Nano, conn.LastRotatedAt); err == nil {
					conn.NextRotationDueAt = ts.Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
				}
			}
		}
		if input.Status != "" {
			switch ConnectionStatus(input.Status) {
			case ConnectionStatusActive, ConnectionStatusDisabled:
				conn.Status = ConnectionStatus(input.Status)
			default:
				return fmt.Errorf("invalid status: %s", input.Status)
			}
		}
		conn.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

		payload, err := json.Marshal(conn)
		if err != nil {
			return err
		}
		if err := txn.Set(metaKey(id), payload); err != nil {
			return err
		}

		updated = conn
		return nil
	})
	if err != nil {
		return Connection{}, err
	}

	return updated, nil
}

func (s *Service) DeleteConnection(id string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		if _, err := txn.Get(metaKey(id)); errors.Is(err, badger.ErrKeyNotFound) {
			return ErrConnectionNotFound
		} else if err != nil {
			return err
		}

		keysToDelete := make([][]byte, 0, 8)
		keysToDelete = append(keysToDelete, metaKey(id))

		secretPrefix := []byte(fmt.Sprintf("%s%s/secret/", keyConnectionPrefix, id))
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek(secretPrefix); it.ValidForPrefix(secretPrefix); it.Next() {
			keyCopy := append([]byte(nil), it.Item().Key()...)
			keysToDelete = append(keysToDelete, keyCopy)
		}

		for _, key := range keysToDelete {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) RotateSecret(id string, input RotateSecretInput) (Connection, error) {
	var updated Connection
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(metaKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrConnectionNotFound
		}
		if err != nil {
			return err
		}

		var conn Connection
		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &conn)
		}); err != nil {
			return err
		}

		currentSecrets, err := s.getSecretVersionMapTxn(txn, conn.ID, conn.SecretVersion)
		if err != nil {
			return err
		}
		nextSecrets, changed, err := mergeSecrets(currentSecrets, input.Secrets)
		if err != nil {
			return err
		}
		if !changed {
			return errors.New("secrets are required")
		}
		if strings.TrimSpace(conn.AuthSecretKey) == "" {
			return errors.New("auth_secret_key is required")
		}
		if _, ok := nextSecrets[conn.AuthSecretKey]; !ok {
			return fmt.Errorf("auth_secret_key %q is missing from provided secrets", conn.AuthSecretKey)
		}

		nextVersion := conn.SecretVersion + 1
		secretPayload, err := marshalSecretsPayload(nextSecrets)
		if err != nil {
			return err
		}
		secretBlob, err := s.encryptSecret(conn.ID, nextVersion, secretPayload)
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		conn.SecretVersion = nextVersion
		conn.LastRotatedAt = now.Format(time.RFC3339Nano)
		conn.UpdatedAt = now.Format(time.RFC3339Nano)
		conn.CredentialKeys = sortedSecretKeys(nextSecrets)
		if conn.RotationIntervalDays > 0 {
			conn.NextRotationDueAt = now.Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour).Format(time.RFC3339Nano)
		}

		metaBytes, err := json.Marshal(conn)
		if err != nil {
			return err
		}
		secretBytes, err := json.Marshal(secretBlob)
		if err != nil {
			return err
		}

		if err := txn.Set(metaKey(conn.ID), metaBytes); err != nil {
			return err
		}
		if err := txn.Set(secretKey(conn.ID, conn.SecretVersion), secretBytes); err != nil {
			return err
		}

		updated = conn
		return nil
	})
	if err != nil {
		return Connection{}, err
	}

	return updated, nil
}

func (s *Service) RecordTestResult(id string, status string, httpStatus int, testErr string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(metaKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrConnectionNotFound
		}
		if err != nil {
			return err
		}

		var conn Connection
		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &conn)
		}); err != nil {
			return err
		}

		conn.LastTestedAt = time.Now().UTC().Format(time.RFC3339Nano)
		conn.LastTestStatus = status
		conn.LastTestHTTPStatus = httpStatus
		conn.LastTestError = sanitizeError(testErr)
		conn.UpdatedAt = conn.LastTestedAt

		payload, err := json.Marshal(conn)
		if err != nil {
			return err
		}
		return txn.Set(metaKey(id), payload)
	})
}

func (s *Service) getSecretVersionMap(id string, version int) (map[string]string, error) {
	var secrets map[string]string
	err := s.db.View(func(txn *badger.Txn) error {
		var innerErr error
		secrets, innerErr = s.getSecretVersionMapTxn(txn, id, version)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *Service) getSecretVersionMapTxn(txn *badger.Txn, id string, version int) (map[string]string, error) {
	var secretBlob encryptedSecret
	item, err := txn.Get(secretKey(id, version))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, ErrConnectionNotFound
	}
	if err != nil {
		return nil, err
	}
	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &secretBlob)
	})
	if err != nil {
		return nil, err
	}

	payload, err := s.decryptSecret(id, version, secretBlob)
	if err != nil {
		return nil, err
	}

	secrets, err := unmarshalSecretsPayload(payload)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *Service) encryptSecret(connectionID string, version int, plaintext string) (encryptedSecret, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedSecret{}, err
	}

	aad := []byte(fmt.Sprintf("%s:%d", connectionID, version))
	ciphertext := s.aead.Seal(nil, nonce, []byte(plaintext), aad)

	return encryptedSecret{
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (s *Service) decryptSecret(connectionID string, version int, blob encryptedSecret) (string, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return "", err
	}
	aad := []byte(fmt.Sprintf("%s:%d", connectionID, version))
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func normalizeCreateInput(input CreateConnectionInput) (Connection, map[string]string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	id := strings.TrimSpace(input.ID)
	if id == "" {
		id = slugify(input.Name)
	}
	if id == "" {
		return Connection{}, nil, errors.New("id or name is required")
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = id
	}

	baseURL := strings.TrimSpace(input.BaseURL)
	if baseURL == "" {
		return Connection{}, nil, errors.New("base_url is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return Connection{}, nil, fmt.Errorf("invalid base_url: %w", err)
	}

	mode := AuthMode(strings.TrimSpace(input.AuthMode))
	switch mode {
	case "":
		mode = AuthModeBearer
	case AuthModeBearer, AuthModeHeaderKey:
	default:
		return Connection{}, nil, fmt.Errorf("invalid auth_mode: %s", input.AuthMode)
	}

	authHeaderName := strings.TrimSpace(input.AuthHeaderName)
	if authHeaderName == "" {
		authHeaderName = "Authorization"
	}

	authPrefix := input.AuthPrefix
	if authPrefix == "" {
		authPrefix = "Bearer "
	}
	if mode == AuthModeHeaderKey && input.AuthPrefix == "" {
		authPrefix = ""
	}

	secrets, err := normalizeSecretsMap(input.Secrets)
	if err != nil {
		return Connection{}, nil, err
	}

	authSecretKey := strings.TrimSpace(input.AuthSecretKey)
	if authSecretKey == "" {
		return Connection{}, nil, errors.New("auth_secret_key is required")
	}
	if _, ok := secrets[authSecretKey]; !ok {
		return Connection{}, nil, fmt.Errorf("auth_secret_key %q is not present in secrets", authSecretKey)
	}

	conn := Connection{
		ID:                  id,
		Name:                name,
		BaseURL:             strings.TrimRight(baseURL, "/"),
		PathPrefix:          normalizePathPrefix(input.PathPrefix),
		AuthMode:            mode,
		AuthHeaderName:      authHeaderName,
		AuthPrefix:          authPrefix,
		AuthSecretKey:       authSecretKey,
		CredentialKeys:      sortedSecretKeys(secrets),
		Status:              ConnectionStatusActive,
		CreatedAt:           now,
		UpdatedAt:           now,
		LastRotatedAt:       now,
		SecretVersion:       1,
		RotationIntervalDays: input.RotationIntervalDays,
	}
	if conn.RotationIntervalDays > 0 {
		conn.NextRotationDueAt = time.Now().UTC().Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	}

	return conn, secrets, nil
}

func metaKey(id string) []byte {
	return []byte(fmt.Sprintf("%s%s/meta", keyConnectionPrefix, id))
}

func secretKey(id string, version int) []byte {
	return []byte(fmt.Sprintf("%s%s/secret/%d", keyConnectionPrefix, id, version))
}

func normalizePathPrefix(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

func normalizeSecretsMap(secrets map[string]string) (map[string]string, error) {
	normalized := make(map[string]string, len(secrets))
	for key, value := range secrets {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return nil, errors.New("secret key cannot be empty")
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		normalized[trimmedKey] = trimmedValue
	}
	if len(normalized) == 0 {
		return nil, errors.New("secrets are required")
	}
	return normalized, nil
}

func mergeSecrets(current map[string]string, secrets map[string]string) (map[string]string, bool, error) {
	next := make(map[string]string, len(current)+len(secrets))
	for key, value := range current {
		next[key] = value
	}

	changed := false
	for key, value := range secrets {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return nil, false, errors.New("secret key cannot be empty")
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		if existing, ok := next[trimmedKey]; !ok || existing != trimmedValue {
			next[trimmedKey] = trimmedValue
			changed = true
		}
	}

	return next, changed, nil
}

func marshalSecretsPayload(values map[string]string) (string, error) {
	payload, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func unmarshalSecretsPayload(payload string) (map[string]string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil, errors.New("secret payload is empty")
	}

	var values map[string]string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil, errors.New("invalid secret payload")
	}

	normalized, err := normalizeSecretsMap(values)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func sortedSecretKeys(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sanitizeError(message string) string {
	trimmed := strings.TrimSpace(message)
	if len(trimmed) > 240 {
		return trimmed[:240]
	}
	return trimmed
}

func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

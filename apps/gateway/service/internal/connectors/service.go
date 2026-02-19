package connectors

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyConnectionPrefix       = "conn/"
	keyCredentialVarPrefix    = "credvar/"
	variableRefSuffix         = "}}"
	maxCredentialVariableSize = 16 * 1024
)

var (
	ErrConnectionNotFound         = errors.New("connection not found")
	ErrConnectionExists           = errors.New("connection already exists")
	ErrCredentialVariableNotFound = errors.New("credential variable not found")
)

type encryptedSecret struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type credentialVariableRecord struct {
	Key              string    `json:"key"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	CreatedBySubject string    `json:"created_by_subject,omitempty"`
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
				normalizeStoredConnection(&conn)
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
	normalizeStoredConnection(&conn)
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
	resolvedSecrets, err := s.resolveVariableReferences(secrets)
	if err != nil {
		return ProxyConfig{}, err
	}
	authSecretKey := strings.TrimSpace(conn.AuthSecretKey)
	secret := ""
	if authSecretKey != "" {
		value, ok := resolvedSecrets[authSecretKey]
		if !ok || strings.TrimSpace(value) == "" {
			return ProxyConfig{}, fmt.Errorf("connection %q missing configured secret key %q", id, authSecretKey)
		}
		secret = value
	}

	return ProxyConfig{
		Connection: conn,
		Secret:     secret,
		Secrets:    resolvedSecrets,
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
		normalizeStoredConnection(&conn)

		if strings.TrimSpace(input.Name) != "" {
			conn.Name = strings.TrimSpace(input.Name)
		}
		if input.PathPrefix != "" {
			conn.PathPrefix = normalizePathPrefix(input.PathPrefix)
		}
		modeChanged := false
		if strings.TrimSpace(input.AuthMode) != "" {
			nextMode, err := parseAuthMode(input.AuthMode)
			if err != nil {
				return err
			}
			if conn.AuthMode != nextMode {
				modeChanged = true
			}
			conn.AuthMode = nextMode
		}
		if strings.TrimSpace(input.AuthHeaderName) != "" {
			conn.AuthHeaderName = strings.TrimSpace(input.AuthHeaderName)
		} else if modeChanged {
			switch conn.AuthMode {
			case AuthModeQueryParam:
				conn.AuthHeaderName = "api_key"
			default:
				if strings.TrimSpace(conn.AuthHeaderName) == "" {
					conn.AuthHeaderName = "Authorization"
				}
			}
		}
		if input.AuthPrefix != "" {
			conn.AuthPrefix = input.AuthPrefix
		} else if modeChanged {
			switch conn.AuthMode {
			case AuthModeBearer:
				conn.AuthPrefix = "Bearer "
			case AuthModeHeaderKey, AuthModeQueryParam:
				conn.AuthPrefix = ""
			}
		}
		if conn.AuthMode == AuthModeQueryParam && strings.TrimSpace(conn.AuthHeaderName) == "" {
			conn.AuthHeaderName = "api_key"
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
			if !conn.LastRotatedAt.IsZero() {
				conn.NextRotationDueAt = conn.LastRotatedAt.Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour).UTC()
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
		if input.MCPEndpoint != "" {
			if !IsMCPConnection(conn) {
				return errors.New("mcp fields can only be updated when protocol is mcp")
			}
			conn.MCPEndpoint = normalizeMCPEndpoint(input.MCPEndpoint)
		}
		if strings.TrimSpace(input.MCPTransport) != "" {
			if !IsMCPConnection(conn) {
				return errors.New("mcp fields can only be updated when protocol is mcp")
			}
			transport, err := parseMCPTransport(input.MCPTransport)
			if err != nil {
				return err
			}
			conn.MCPTransport = transport
		}
		if input.MCPToolAllowlist != nil || input.MCPToolDenylist != nil || input.MCPMaxToolsExposed != nil {
			if !IsMCPConnection(conn) {
				return errors.New("mcp fields can only be updated when protocol is mcp")
			}
			policy := conn.MCPToolPolicy
			if input.MCPToolAllowlist != nil {
				policy.Allowlist = normalizeToolNameList(input.MCPToolAllowlist)
			}
			if input.MCPToolDenylist != nil {
				policy.Denylist = normalizeToolNameList(input.MCPToolDenylist)
			}
			if input.MCPMaxToolsExposed != nil {
				if *input.MCPMaxToolsExposed < 0 {
					return errors.New("mcp_max_tools_exposed must be >= 0")
				}
				policy.MaxToolsExposed = *input.MCPMaxToolsExposed
			}
			conn.MCPToolPolicy = policy
		}
		if input.MCPSubjectToolPolicies != nil {
			if !IsMCPConnection(conn) {
				return errors.New("mcp fields can only be updated when protocol is mcp")
			}
			normalized, err := normalizeSubjectToolPolicies(input.MCPSubjectToolPolicies)
			if err != nil {
				return err
			}
			conn.MCPSubjectToolPolicies = normalized
		}
		conn.UpdatedAt = time.Now().UTC()

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

func (s *Service) SaveMCPDiscovery(id string, discovery MCPDiscovery) (Connection, error) {
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
		normalizeStoredConnection(&conn)
		if !IsMCPConnection(conn) {
			return fmt.Errorf("connection %q is not an mcp connection", id)
		}

		if discovery.LastDiscoveredAt.IsZero() {
			discovery.LastDiscoveredAt = time.Now().UTC()
		}
		discovery.LastDiscoveryError = sanitizeError(discovery.LastDiscoveryError)
		discovery.Tools = normalizeMCPTools(discovery.Tools)
		conn.MCPDiscovery = discovery
		conn.UpdatedAt = time.Now().UTC()

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
		normalizeStoredConnection(&conn)

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
		if authSecretKey := strings.TrimSpace(conn.AuthSecretKey); authSecretKey != "" {
			if _, ok := nextSecrets[authSecretKey]; !ok {
				return fmt.Errorf("auth_secret_key %q is missing from provided secrets", authSecretKey)
			}
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
		conn.LastRotatedAt = now
		conn.UpdatedAt = now
		conn.CredentialKeys = sortedSecretKeys(nextSecrets)
		if conn.RotationIntervalDays > 0 {
			conn.NextRotationDueAt = now.Add(time.Duration(conn.RotationIntervalDays) * 24 * time.Hour)
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

		conn.LastTestedAt = time.Now().UTC()
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

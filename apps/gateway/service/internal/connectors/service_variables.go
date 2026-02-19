package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

func (s *Service) ListCredentialVariables() ([]SharedCredentialVariable, error) {
	variables := make([]SharedCredentialVariable, 0, 8)

	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte(keyCredentialVarPrefix)); it.ValidForPrefix([]byte(keyCredentialVarPrefix)); it.Next() {
			item := it.Item()
			key := string(item.Key())
			if !strings.HasSuffix(key, "/meta") {
				continue
			}

			if err := item.Value(func(val []byte) error {
				var record credentialVariableRecord
				if err := json.Unmarshal(val, &record); err != nil {
					return err
				}
				variables = append(variables, SharedCredentialVariable{
					Key:              record.Key,
					CreatedAt:        record.CreatedAt,
					UpdatedAt:        record.UpdatedAt,
					CreatedBySubject: record.CreatedBySubject,
				})
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(variables, func(i, j int) bool { return variables[i].Key < variables[j].Key })
	return variables, nil
}

func (s *Service) UpsertCredentialVariable(input UpsertSharedCredentialVariableInput) (SharedCredentialVariable, error) {
	key := strings.TrimSpace(input.Key)
	if key == "" {
		return SharedCredentialVariable{}, errors.New("key is required")
	}
	if !isValidCredentialVariableKey(key) {
		return SharedCredentialVariable{}, errors.New("key must contain only letters, numbers, ., _, or -")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return SharedCredentialVariable{}, errors.New("value is required")
	}
	if len(value) > maxCredentialVariableSize {
		return SharedCredentialVariable{}, fmt.Errorf("value exceeds %d bytes", maxCredentialVariableSize)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	createdBySubject := strings.TrimSpace(input.CreatedBySubject)
	var out SharedCredentialVariable

	err := s.db.Update(func(txn *badger.Txn) error {
		var record credentialVariableRecord

		metaItem, err := txn.Get(variableMetaKey(key))
		if err == nil {
			if err := metaItem.Value(func(val []byte) error {
				return json.Unmarshal(val, &record)
			}); err != nil {
				return err
			}
			record.UpdatedAt = now
			if record.CreatedBySubject == "" && createdBySubject != "" {
				record.CreatedBySubject = createdBySubject
			}
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			record = credentialVariableRecord{
				Key:              key,
				CreatedAt:        now,
				UpdatedAt:        now,
				CreatedBySubject: createdBySubject,
			}
		} else {
			return err
		}

		blob, err := s.encryptCredentialVariable(key, value)
		if err != nil {
			return err
		}
		metaBytes, err := json.Marshal(record)
		if err != nil {
			return err
		}
		secretBytes, err := json.Marshal(blob)
		if err != nil {
			return err
		}
		if err := txn.Set(variableMetaKey(key), metaBytes); err != nil {
			return err
		}
		if err := txn.Set(variableSecretKey(key), secretBytes); err != nil {
			return err
		}

		out = SharedCredentialVariable{
			Key:              record.Key,
			CreatedAt:        record.CreatedAt,
			UpdatedAt:        record.UpdatedAt,
			CreatedBySubject: record.CreatedBySubject,
		}
		return nil
	})
	if err != nil {
		return SharedCredentialVariable{}, err
	}
	return out, nil
}

func (s *Service) DeleteCredentialVariable(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return errors.New("key is required")
	}

	return s.db.Update(func(txn *badger.Txn) error {
		if _, err := txn.Get(variableMetaKey(trimmed)); errors.Is(err, badger.ErrKeyNotFound) {
			return ErrCredentialVariableNotFound
		} else if err != nil {
			return err
		}
		if err := txn.Delete(variableMetaKey(trimmed)); err != nil {
			return err
		}
		if err := txn.Delete(variableSecretKey(trimmed)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
	})
}

func (s *Service) resolveVariableReferences(values map[string]string) (map[string]string, error) {
	if len(values) == 0 {
		return map[string]string{}, nil
	}
	resolved := make(map[string]string, len(values))
	cache := map[string]string{}
	for key, value := range values {
		refKey, ok := parseCredentialVariableReference(value)
		if !ok {
			resolved[key] = value
			continue
		}
		if cached, exists := cache[refKey]; exists {
			resolved[key] = cached
			continue
		}
		resolvedValue, err := s.getCredentialVariableValue(refKey)
		if err != nil {
			return nil, fmt.Errorf("resolve secret %q: %w", key, err)
		}
		cache[refKey] = resolvedValue
		resolved[key] = resolvedValue
	}
	return resolved, nil
}

func (s *Service) getCredentialVariableValue(key string) (string, error) {
	var blob encryptedSecret
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(variableSecretKey(key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ErrCredentialVariableNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &blob)
		})
	})
	if err != nil {
		return "", err
	}
	value, err := s.decryptCredentialVariable(key, blob)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("credential variable %q has empty value", key)
	}
	return trimmed, nil
}

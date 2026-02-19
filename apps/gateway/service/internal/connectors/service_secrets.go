package connectors

import (
	"encoding/json"
	"errors"

	"github.com/dgraph-io/badger/v4"
)

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

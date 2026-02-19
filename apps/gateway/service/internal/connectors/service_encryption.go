package connectors

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

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

func (s *Service) encryptCredentialVariable(key string, plaintext string) (encryptedSecret, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedSecret{}, err
	}
	aad := []byte("credvar:" + key)
	ciphertext := s.aead.Seal(nil, nonce, []byte(plaintext), aad)
	return encryptedSecret{
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (s *Service) decryptCredentialVariable(key string, blob encryptedSecret) (string, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return "", err
	}
	aad := []byte("credvar:" + key)
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

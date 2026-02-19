package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func extractSigilumIdentity(headers http.Header) (namespace string, publicKey string, subject string, err error) {
	namespace = strings.TrimSpace(headers.Get(headerNamespace))
	if namespace == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerNamespace)
	}
	subject = strings.TrimSpace(headers.Get(headerSubject))
	if subject == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerSubject)
	}
	publicKey = strings.TrimSpace(headers.Get(headerAgentKey))
	if publicKey == "" {
		return "", "", "", fmt.Errorf("missing %s header", headerAgentKey)
	}
	return namespace, publicKey, subject, nil
}

func validateSigilumAuthHeaders(headers http.Header) error {
	for _, header := range []string{
		headerSignatureInput,
		headerSignature,
		headerNamespace,
		headerSubject,
		headerAgentKey,
		headerAgentCert,
	} {
		if len(headers.Values(header)) > 1 {
			return fmt.Errorf("duplicate %s header", header)
		}
	}
	return nil
}

func extractSignatureNonce(signatureInput string) (string, error) {
	needle := `;nonce="`
	index := strings.Index(signatureInput, needle)
	if index < 0 {
		return "", errors.New("invalid signature-input: missing nonce")
	}
	start := index + len(needle)
	end := strings.Index(signatureInput[start:], `"`)
	if end < 0 {
		return "", errors.New("invalid signature-input: malformed nonce")
	}
	nonce := strings.TrimSpace(signatureInput[start : start+end])
	if nonce == "" {
		return "", errors.New("invalid signature-input: empty nonce")
	}
	return nonce, nil
}

func validateSignatureComponents(signatureInput string, hasBody bool) error {
	components, err := parseSignatureComponents(signatureInput)
	if err != nil {
		return err
	}

	expected := []string{"@method", "@target-uri", "sigilum-namespace", "sigilum-subject", "sigilum-agent-key", "sigilum-agent-cert"}
	if hasBody {
		expected = []string{"@method", "@target-uri", "content-digest", "sigilum-namespace", "sigilum-subject", "sigilum-agent-key", "sigilum-agent-cert"}
	}
	if len(components) != len(expected) {
		return errInvalidSignedComponentSet
	}
	for idx := range expected {
		if components[idx] != expected[idx] {
			return errInvalidSignedComponentSet
		}
	}
	return nil
}

func parseSignatureComponents(signatureInput string) ([]string, error) {
	value := strings.TrimSpace(signatureInput)
	if value == "" {
		return nil, errInvalidSignatureInputFormat
	}
	const prefix = "sig1=("
	const createdMarker = ");created="
	if !strings.HasPrefix(value, prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	end := strings.Index(value, createdMarker)
	if end < 0 || end <= len(prefix) {
		return nil, errInvalidSignatureInputFormat
	}
	raw := strings.TrimSpace(value[len(prefix):end])
	if raw == "" {
		return nil, errInvalidSignatureInputFormat
	}

	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		return nil, errInvalidSignatureInputFormat
	}

	components := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
			return nil, errInvalidSignatureInputFormat
		}
		component := strings.TrimSpace(token[1 : len(token)-1])
		if component == "" {
			return nil, errInvalidSignatureInputFormat
		}
		components = append(components, component)
	}
	return components, nil
}

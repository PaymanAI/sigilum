package sigilum

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type rfcFixture struct {
	Fixed struct {
		Created int64  `json:"created"`
		Nonce   string `json:"nonce"`
	} `json:"fixed"`
	Vectors []struct {
		Name                  string   `json:"name"`
		Method                string   `json:"method"`
		URL                   string   `json:"url"`
		Body                  *string  `json:"body"`
		ExpectedTargetURI     string   `json:"expected_target_uri"`
		ExpectedContentDigest string   `json:"expected_content_digest"`
		ExpectedComponents    []string `json:"expected_components"`
	} `json:"vectors"`
}

func loadRFCFixture(t *testing.T) rfcFixture {
	t.Helper()
	path := filepath.Join("..", "..", "shared", "test-vectors", "http-signatures-rfc9421.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture rfcFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return fixture
}

func TestRFC9421ProfileVectorsAndStrictChecks(t *testing.T) {
	fixture := loadRFCFixture(t)
	tmp := t.TempDir()
	if _, err := InitIdentity(InitIdentityOptions{Namespace: "alice", HomeDir: tmp}); err != nil {
		t.Fatalf("init identity: %v", err)
	}
	identity, err := LoadIdentity(LoadIdentityOptions{Namespace: "alice", HomeDir: tmp})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	for _, vector := range fixture.Vectors {
		var body []byte
		if vector.Body != nil {
			body = []byte(*vector.Body)
		}

		signed, err := SignHTTPRequest(identity, SignRequestInput{
			URL:     vector.URL,
			Method:  vector.Method,
			Body:    body,
			Created: fixture.Fixed.Created,
			Nonce:   fixture.Fixed.Nonce,
		})
		if err != nil {
			t.Fatalf("sign %s: %v", vector.Name, err)
		}

		if signed.URL != vector.ExpectedTargetURI {
			t.Fatalf("%s: unexpected URL: %s", vector.Name, signed.URL)
		}
		signatureInput := signed.Headers["signature-input"]
		if !strings.Contains(signatureInput, "created="+strconv.FormatInt(fixture.Fixed.Created, 10)) {
			t.Fatalf("%s: created missing in Signature-Input: %s", vector.Name, signatureInput)
		}
		if !strings.Contains(signatureInput, "nonce=\""+fixture.Fixed.Nonce+"\"") {
			t.Fatalf("%s: nonce missing in Signature-Input: %s", vector.Name, signatureInput)
		}
		expectedComponents := "(" + quoteComponents(vector.ExpectedComponents) + ")"
		if !strings.Contains(signatureInput, expectedComponents) {
			t.Fatalf("%s: components mismatch in Signature-Input: %s", vector.Name, signatureInput)
		}
		if vector.ExpectedContentDigest != "" && signed.Headers["content-digest"] != vector.ExpectedContentDigest {
			t.Fatalf("%s: digest mismatch", vector.Name)
		}

		seen := map[string]struct{}{}
		ok := VerifyHTTPSignature(VerifySignatureInput{
			URL:               signed.URL,
			Method:            signed.Method,
			Headers:           signed.Headers,
			Body:              signed.Body,
			ExpectedNamespace: "alice",
			NowUnix:           fixture.Fixed.Created + 5,
			MaxAgeSeconds:     60,
			SeenNonces:        seen,
		})
		if !ok.Valid {
			t.Fatalf("%s: expected valid strict verify, got: %s", vector.Name, ok.Reason)
		}

		replay := VerifyHTTPSignature(VerifySignatureInput{
			URL:               signed.URL,
			Method:            signed.Method,
			Headers:           signed.Headers,
			Body:              signed.Body,
			ExpectedNamespace: "alice",
			NowUnix:           fixture.Fixed.Created + 5,
			MaxAgeSeconds:     60,
			SeenNonces:        seen,
		})
		if replay.Valid || !strings.Contains(strings.ToLower(replay.Reason), "replay") {
			t.Fatalf("%s: expected replay detection, got: %#v", vector.Name, replay)
		}

		stale := VerifyHTTPSignature(VerifySignatureInput{
			URL:               signed.URL,
			Method:            signed.Method,
			Headers:           signed.Headers,
			Body:              signed.Body,
			ExpectedNamespace: "alice",
			NowUnix:           fixture.Fixed.Created + 500,
			MaxAgeSeconds:     60,
		})
		if stale.Valid || (!strings.Contains(strings.ToLower(stale.Reason), "expired") && !strings.Contains(strings.ToLower(stale.Reason), "valid")) {
			t.Fatalf("%s: expected stale signature rejection, got: %#v", vector.Name, stale)
		}
	}
}

func quoteComponents(components []string) string {
	quoted := make([]string, 0, len(components))
	for _, c := range components {
		quoted = append(quoted, "\""+c+"\"")
	}
	return strings.Join(quoted, " ")
}


package config

import "testing"

func TestParseTrustedProxyCIDRs(t *testing.T) {
	cidrs, err := parseTrustedProxyCIDRs("203.0.113.0/24, 10.0.0.1, 2001:db8::/32")
	if err != nil {
		t.Fatalf("expected parse success, got error: %v", err)
	}
	if len(cidrs) != 3 {
		t.Fatalf("expected 3 cidr entries, got %d", len(cidrs))
	}
	if got := cidrs[1].String(); got != "10.0.0.1/32" {
		t.Fatalf("expected single IPv4 to normalize to /32, got %q", got)
	}
}

func TestParseTrustedProxyCIDRsRejectsInvalidEntry(t *testing.T) {
	if _, err := parseTrustedProxyCIDRs("not-a-cidr"); err == nil {
		t.Fatalf("expected parse failure for invalid entry")
	}
}

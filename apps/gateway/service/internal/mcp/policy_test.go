package mcp

import (
	"testing"

	"sigilum.local/gateway/internal/connectors"
)

func TestEffectiveToolPolicySubjectCannotExpandBaseAllowlist(t *testing.T) {
	base := connectors.MCPToolPolicy{
		Allowlist:       []string{"accounts.read", "payments.create"},
		Denylist:        []string{"payments.refund"},
		MaxToolsExposed: 10,
	}
	subjectPolicies := map[string]connectors.MCPToolPolicy{
		"user-1": {
			Allowlist:       []string{"payments.create", "admin.reset"},
			Denylist:        []string{"accounts.read"},
			MaxToolsExposed: 2,
		},
	}

	effective := EffectiveToolPolicy(base, "user-1", subjectPolicies)

	if len(effective.Allowlist) != 1 || effective.Allowlist[0] != "payments.create" {
		t.Fatalf("expected intersected allowlist, got %#v", effective.Allowlist)
	}
	if len(effective.Denylist) != 2 {
		t.Fatalf("expected denylist union, got %#v", effective.Denylist)
	}
	if effective.MaxToolsExposed != 2 {
		t.Fatalf("expected tighter max tools exposed, got %d", effective.MaxToolsExposed)
	}
}

func TestFilterToolsHonorsAllowDenyAndMax(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "accounts.read"},
		{Name: "payments.create"},
		{Name: "payments.refund"},
	}
	policy := connectors.MCPToolPolicy{
		Allowlist:       []string{"accounts.read", "payments.create", "payments.refund"},
		Denylist:        []string{"accounts.read"},
		MaxToolsExposed: 1,
	}

	filtered := FilterTools(tools, policy)
	if len(filtered) != 1 {
		t.Fatalf("expected one tool after max limit, got %d", len(filtered))
	}
	if filtered[0].Name != "payments.create" {
		t.Fatalf("expected payments.create to remain, got %s", filtered[0].Name)
	}
}

func TestToolAllowed(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "linear.searchIssues"},
		{Name: "linear.createComment"},
	}
	policy := connectors.MCPToolPolicy{
		Allowlist: []string{"linear.searchIssues"},
	}

	if !ToolAllowed("linear.searchIssues", tools, policy) {
		t.Fatal("expected tool to be allowed")
	}
	if ToolAllowed("linear.createComment", tools, policy) {
		t.Fatal("expected tool to be denied")
	}
}

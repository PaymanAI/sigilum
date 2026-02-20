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

func TestExplainToolDecisionAllowed(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "linear.searchIssues"},
		{Name: "linear.createComment"},
	}
	policy := connectors.MCPToolPolicy{
		Allowlist: []string{"linear.searchIssues"},
	}

	decision := ExplainToolDecision("linear.searchIssues", tools, policy)

	if !decision.Allowed {
		t.Fatalf("expected tool to be allowed, got decision %#v", decision)
	}
	if decision.ReasonCode != ToolDecisionAllowed {
		t.Fatalf("expected reason %s, got %s", ToolDecisionAllowed, decision.ReasonCode)
	}
	if !decision.ToolDiscovered {
		t.Fatal("expected tool_discovered to be true")
	}
	if len(decision.ExposedTools) != 1 || decision.ExposedTools[0] != "linear.searchIssues" {
		t.Fatalf("expected exposed tools to contain only linear.searchIssues, got %#v", decision.ExposedTools)
	}
}

func TestExplainToolDecisionDeniedByAllowlist(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "linear.searchIssues"},
		{Name: "linear.createComment"},
	}
	policy := connectors.MCPToolPolicy{
		Allowlist: []string{"linear.searchIssues"},
	}

	decision := ExplainToolDecision("linear.createComment", tools, policy)

	if decision.Allowed {
		t.Fatalf("expected tool to be denied, got decision %#v", decision)
	}
	if decision.ReasonCode != ToolDecisionDeniedByAllowlist {
		t.Fatalf("expected reason %s, got %s", ToolDecisionDeniedByAllowlist, decision.ReasonCode)
	}
}

func TestExplainToolDecisionDeniedByDenylist(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "linear.searchIssues"},
		{Name: "linear.createComment"},
	}
	policy := connectors.MCPToolPolicy{
		Denylist: []string{"linear.createComment"},
	}

	decision := ExplainToolDecision("linear.createComment", tools, policy)

	if decision.Allowed {
		t.Fatalf("expected tool to be denied, got decision %#v", decision)
	}
	if decision.ReasonCode != ToolDecisionDeniedByDenylist {
		t.Fatalf("expected reason %s, got %s", ToolDecisionDeniedByDenylist, decision.ReasonCode)
	}
}

func TestExplainToolDecisionDeniedByMaxToolsExposed(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "a"},
		{Name: "b"},
	}
	policy := connectors.MCPToolPolicy{
		MaxToolsExposed: 1,
	}

	decision := ExplainToolDecision("b", tools, policy)

	if decision.Allowed {
		t.Fatalf("expected tool to be denied, got decision %#v", decision)
	}
	if decision.ReasonCode != ToolDecisionDeniedByMaxToolsExposed {
		t.Fatalf("expected reason %s, got %s", ToolDecisionDeniedByMaxToolsExposed, decision.ReasonCode)
	}
}

func TestExplainToolDecisionNotDiscovered(t *testing.T) {
	tools := []connectors.MCPTool{
		{Name: "linear.searchIssues"},
	}

	decision := ExplainToolDecision("linear.createComment", tools, connectors.MCPToolPolicy{})

	if decision.Allowed {
		t.Fatalf("expected tool to be denied, got decision %#v", decision)
	}
	if decision.ReasonCode != ToolDecisionNotDiscovered {
		t.Fatalf("expected reason %s, got %s", ToolDecisionNotDiscovered, decision.ReasonCode)
	}
	if decision.ToolDiscovered {
		t.Fatal("expected tool_discovered to be false")
	}
}

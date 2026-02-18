package mcp

import (
	"sort"
	"strings"

	"sigilum.local/gateway/internal/connectors"
)

func EffectiveToolPolicy(
	base connectors.MCPToolPolicy,
	subject string,
	subjectPolicies map[string]connectors.MCPToolPolicy,
) connectors.MCPToolPolicy {
	effective := connectors.MCPToolPolicy{
		Allowlist:       cloneList(base.Allowlist),
		Denylist:        cloneList(base.Denylist),
		MaxToolsExposed: base.MaxToolsExposed,
	}

	subjectPolicy, ok := subjectPolicies[strings.TrimSpace(subject)]
	if !ok {
		return normalizePolicy(effective)
	}

	if len(subjectPolicy.Allowlist) > 0 {
		if len(effective.Allowlist) == 0 {
			effective.Allowlist = cloneList(subjectPolicy.Allowlist)
		} else {
			effective.Allowlist = intersectLists(effective.Allowlist, subjectPolicy.Allowlist)
		}
	}
	effective.Denylist = unionLists(effective.Denylist, subjectPolicy.Denylist)
	effective.MaxToolsExposed = minPositive(base.MaxToolsExposed, subjectPolicy.MaxToolsExposed)

	return normalizePolicy(effective)
}

func FilterTools(tools []connectors.MCPTool, policy connectors.MCPToolPolicy) []connectors.MCPTool {
	policy = normalizePolicy(policy)
	allowSet := toSet(policy.Allowlist)
	denySet := toSet(policy.Denylist)

	filtered := make([]connectors.MCPTool, 0, len(tools))
	seen := map[string]struct{}{}
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}

		if len(allowSet) > 0 {
			if _, allowed := allowSet[name]; !allowed {
				continue
			}
		}
		if _, denied := denySet[name]; denied {
			continue
		}

		filtered = append(filtered, connectors.MCPTool{
			Name:        name,
			Description: strings.TrimSpace(tool.Description),
			InputSchema: strings.TrimSpace(tool.InputSchema),
		})
		if policy.MaxToolsExposed > 0 && len(filtered) >= policy.MaxToolsExposed {
			break
		}
	}
	return filtered
}

func ToolAllowed(toolName string, tools []connectors.MCPTool, policy connectors.MCPToolPolicy) bool {
	name := strings.TrimSpace(toolName)
	if name == "" {
		return false
	}
	filtered := FilterTools(tools, policy)
	for _, tool := range filtered {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func normalizePolicy(policy connectors.MCPToolPolicy) connectors.MCPToolPolicy {
	policy.Allowlist = normalizeList(policy.Allowlist)
	policy.Denylist = normalizeList(policy.Denylist)
	if policy.MaxToolsExposed < 0 {
		policy.MaxToolsExposed = 0
	}
	return policy
}

func normalizeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func toSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func cloneList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func intersectLists(a []string, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	bSet := toSet(normalizeList(b))
	out := make([]string, 0, len(a))
	for _, value := range normalizeList(a) {
		if _, ok := bSet[value]; ok {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func unionLists(a []string, b []string) []string {
	return normalizeList(append(cloneList(a), b...))
}

func minPositive(a int, b int) int {
	if a <= 0 {
		if b <= 0 {
			return 0
		}
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

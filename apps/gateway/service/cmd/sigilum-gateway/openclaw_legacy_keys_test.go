package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectLegacyJSONCandidatesAndDelete(t *testing.T) {
	root := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"openai": map[string]any{
					"apiKey": "sk-live-1234567890",
				},
			},
		},
	}

	findings := []legacyKeyCandidate{}
	collectLegacyJSONCandidates(root, "/tmp/openclaw.json", nil, "", &findings)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	candidate := findings[0]
	if candidate.Finding.Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", candidate.Finding.Provider)
	}
	if candidate.Finding.SourceType != string(legacyKeySourceConfig) {
		t.Fatalf("expected source_type %q, got %q", legacyKeySourceConfig, candidate.Finding.SourceType)
	}

	changed := deleteLegacyJSONPath(root, candidate.JSONPath)
	if !changed {
		t.Fatalf("expected deleteLegacyJSONPath to return true")
	}

	models := root["models"].(map[string]any)
	providers := models["providers"].(map[string]any)
	openai := providers["openai"].(map[string]any)
	if _, exists := openai["apiKey"]; exists {
		t.Fatalf("expected apiKey to be deleted")
	}
}

func TestRemoveDotEnvKeys(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, ".env")
	content := strings.Join([]string{
		"OPENAI_API_KEY=sk-live-1234567890",
		"ANTHROPIC_API_KEY=sk-ant-1234567890",
		"KEEP_ME=yes",
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	removed, changed, err := removeDotEnvKeys(envPath, map[string]struct{}{"OPENAI_API_KEY": {}}, true)
	if err != nil {
		t.Fatalf("dry-run removeDotEnvKeys failed: %v", err)
	}
	if !changed || removed != 1 {
		t.Fatalf("expected dry run changed=true removed=1, got changed=%t removed=%d", changed, removed)
	}

	afterDryRun, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env after dry run: %v", err)
	}
	if string(afterDryRun) != content {
		t.Fatalf("expected dry run to leave file unchanged")
	}

	removed, changed, err = removeDotEnvKeys(envPath, map[string]struct{}{"OPENAI_API_KEY": {}}, false)
	if err != nil {
		t.Fatalf("removeDotEnvKeys failed: %v", err)
	}
	if !changed || removed != 1 {
		t.Fatalf("expected changed=true removed=1, got changed=%t removed=%d", changed, removed)
	}

	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env after remove: %v", err)
	}
	text := string(after)
	if strings.Contains(text, "OPENAI_API_KEY") {
		t.Fatalf("expected OPENAI_API_KEY to be removed")
	}
	if !strings.Contains(text, "ANTHROPIC_API_KEY") || !strings.Contains(text, "KEEP_ME=yes") {
		t.Fatalf("expected unrelated keys to remain")
	}
}

func TestChooseImportVariableKeyAvoidsCollision(t *testing.T) {
	used := map[string]struct{}{
		"OPENAI_API_KEY": {},
	}
	candidate := legacyKeyCandidate{
		Finding: legacyKeyFinding{
			Provider: "openai",
			Field:    "OPENAI_API_KEY",
			Variable: "OPENAI_API_KEY",
		},
	}

	next := chooseImportVariableKey(candidate, used)
	if next != "OPENAI_API_KEY_2" {
		t.Fatalf("expected OPENAI_API_KEY_2, got %q", next)
	}
}

func TestProviderFromConnectionID(t *testing.T) {
	if got := providerFromConnectionID("sigilum-secure-openai-mcp"); got != "openai" {
		t.Fatalf("expected openai, got %q", got)
	}
	if got := providerFromConnectionID("sigilum-secure-unknown"); got != "" {
		t.Fatalf("expected empty provider for unknown alias, got %q", got)
	}
}

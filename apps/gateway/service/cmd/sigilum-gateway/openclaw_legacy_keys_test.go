package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigilum.local/gateway/internal/connectors"
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

func TestCollectRuntimeLegacyReportCandidates(t *testing.T) {
	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "legacy-runtime-credentials.json")
	report := runtimeLegacyCredentialReport{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Findings: []runtimeLegacyCredentialItem{
			{
				Provider:   "openai",
				Field:      "OPENAI_API_KEY",
				Variable:   "OPENAI_API_KEY",
				Value:      "sk-live-1234567890",
				SourcePath: "openclaw_runtime_env",
				Location:   "process.env.OPENAI_API_KEY",
			},
			{
				Provider:   "openai",
				Field:      "OPENAI_API_KEY",
				Variable:   "OPENAI_API_KEY",
				Value:      "your_api_key_here",
				SourcePath: "openclaw_runtime_env",
				Location:   "process.env.OPENAI_API_KEY",
			},
		},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(reportPath, encoded, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	findings := []legacyKeyCandidate{}
	warnings := []string{}
	collectRuntimeLegacyReportCandidates(reportPath, &findings, &warnings)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %#v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 runtime finding, got %d", len(findings))
	}
	if findings[0].Finding.SourceType != string(legacyKeySourceRuntimeManifest) {
		t.Fatalf("expected source type %q, got %q", legacyKeySourceRuntimeManifest, findings[0].Finding.SourceType)
	}
	if findings[0].Finding.Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", findings[0].Finding.Provider)
	}
}

func TestPurgeLegacyOpenClawKeysRuntimeFindingAddsWarning(t *testing.T) {
	tmp := t.TempDir()
	openClawHome := filepath.Join(tmp, ".openclaw")
	reportDir := filepath.Join(openClawHome, ".sigilum")
	if err := os.MkdirAll(reportDir, 0o700); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	reportPath := filepath.Join(reportDir, "legacy-runtime-credentials.json")
	report := runtimeLegacyCredentialReport{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Findings: []runtimeLegacyCredentialItem{
			{
				Provider:   "openai",
				Field:      "OPENAI_API_KEY",
				Variable:   "OPENAI_API_KEY",
				Value:      "sk-live-1234567890",
				SourcePath: "openclaw_runtime_env",
				Location:   "process.env.OPENAI_API_KEY",
			},
		},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(reportPath, encoded, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	t.Setenv("OPENCLAW_HOME", openClawHome)
	t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(openClawHome, "openclaw.json"))

	discovered := discoverLegacyOpenClawKeys()
	if discovered.Total != 1 {
		t.Fatalf("expected 1 finding, got %d", discovered.Total)
	}
	result, err := purgeLegacyOpenClawKeys(legacyKeyPurgeRequest{
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("purgeLegacyOpenClawKeys failed: %v", err)
	}
	if result.PurgedCount != 0 {
		t.Fatalf("expected purged_count=0 for runtime-only findings, got %d", result.PurgedCount)
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected warning for runtime-only findings")
	}
	actionFound := false
	for _, action := range result.Actions {
		if action.Type == "manual_runtime_cleanup" {
			actionFound = true
			break
		}
	}
	if !actionFound {
		t.Fatalf("expected manual_runtime_cleanup action")
	}
}

func TestImportLegacyOpenClawKeysCreatesProviderConnections(t *testing.T) {
	tmp := t.TempDir()
	openClawHome := filepath.Join(tmp, ".openclaw")
	if err := os.MkdirAll(openClawHome, 0o700); err != nil {
		t.Fatalf("mkdir openclaw home: %v", err)
	}
	configPath := filepath.Join(openClawHome, "openclaw.json")
	config := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"openai": map[string]any{
					"apiKey": "sk-openai-1234567890",
				},
				"anthropic": map[string]any{
					"apiKey": "sk-ant-1234567890",
				},
			},
		},
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, encodedConfig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("OPENCLAW_HOME", openClawHome)
	t.Setenv("OPENCLAW_CONFIG_PATH", configPath)
	connectorService, err := connectors.NewService(filepath.Join(tmp, "gateway"), "test-master-key")
	if err != nil {
		t.Fatalf("new connector service: %v", err)
	}
	defer connectorService.Close()

	imported, err := importLegacyOpenClawKeys(connectorService, nil, legacyKeyImportRequest{})
	if err != nil {
		t.Fatalf("importLegacyOpenClawKeys failed: %v", err)
	}
	if imported.ImportedCount < 2 {
		t.Fatalf("expected at least 2 imported keys, got %d", imported.ImportedCount)
	}
	if len(imported.SecuredConnections) < 2 {
		t.Fatalf("expected at least 2 secured connections, got %d", len(imported.SecuredConnections))
	}
	if len(imported.ImportedVariable) != 0 {
		t.Fatalf("expected no imported variables, got %#v", imported.ImportedVariable)
	}

	for _, secured := range imported.SecuredConnections {
		resolved, err := connectorService.ResolveProxyConfig(secured.ConnectionID)
		if err != nil {
			t.Fatalf("resolve proxy config for %s: %v", secured.ConnectionID, err)
		}
		if strings.TrimSpace(resolved.Secret) == "" {
			t.Fatalf("expected non-empty resolved secret for %s", secured.ConnectionID)
		}
	}
}

func TestImportLegacyOpenClawKeysUpdatesConnectionDirectly(t *testing.T) {
	tmp := t.TempDir()
	openClawHome := filepath.Join(tmp, ".openclaw")
	if err := os.MkdirAll(openClawHome, 0o700); err != nil {
		t.Fatalf("mkdir openclaw home: %v", err)
	}
	configPath := filepath.Join(openClawHome, "openclaw.json")
	config := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"openai": map[string]any{
					"apiKey": "sk-openai-9876543210",
				},
			},
		},
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, encodedConfig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("OPENCLAW_HOME", openClawHome)
	t.Setenv("OPENCLAW_CONFIG_PATH", configPath)
	connectorService, err := connectors.NewService(filepath.Join(tmp, "gateway"), "test-master-key")
	if err != nil {
		t.Fatalf("new connector service: %v", err)
	}
	defer connectorService.Close()

	connectionID := "sigilum-secure-openai"
	if _, err := connectorService.CreateConnection(connectors.CreateConnectionInput{
		ID:             connectionID,
		Name:           "OpenAI",
		BaseURL:        "https://api.openai.com",
		AuthMode:       "bearer",
		AuthHeaderName: "Authorization",
		AuthPrefix:     "Bearer ",
		AuthSecretKey:  "api_key",
		Secrets: map[string]string{
			"api_key": "sk-old-111122223333",
		},
		RotationIntervalDays: 90,
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	imported, err := importLegacyOpenClawKeys(connectorService, nil, legacyKeyImportRequest{ConnectionID: connectionID})
	if err != nil {
		t.Fatalf("importLegacyOpenClawKeys failed: %v", err)
	}
	if imported.ImportedCount != 1 {
		t.Fatalf("expected imported_count=1, got %d", imported.ImportedCount)
	}
	if imported.ConnectionID != connectionID {
		t.Fatalf("expected connection id %q, got %q", connectionID, imported.ConnectionID)
	}
	if imported.BoundSecretKey != "api_key" {
		t.Fatalf("expected bound secret key api_key, got %q", imported.BoundSecretKey)
	}
	if len(imported.ImportedVariable) != 0 {
		t.Fatalf("expected no imported variables, got %#v", imported.ImportedVariable)
	}

	resolved, err := connectorService.ResolveProxyConfig(connectionID)
	if err != nil {
		t.Fatalf("resolve proxy config: %v", err)
	}
	if resolved.Secret != "sk-openai-9876543210" {
		t.Fatalf("expected updated key, got %q", resolved.Secret)
	}
	variables, err := connectorService.ListCredentialVariables()
	if err != nil {
		t.Fatalf("list variables: %v", err)
	}
	if len(variables) != 0 {
		t.Fatalf("expected no credential variables, got %d", len(variables))
	}
}

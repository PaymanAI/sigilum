package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sigilum.local/gateway/internal/connectors"
)

type legacyKeySourceType string

const (
	legacyKeySourceConfig legacyKeySourceType = "openclaw_config"
	legacyKeySourceDotEnv legacyKeySourceType = "dotenv"
)

type legacyKeyFinding struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	Field      string `json:"field"`
	Variable   string `json:"variable"`
	SourceType string `json:"source_type"`
	SourcePath string `json:"source_path"`
	Location   string `json:"location"`
	Masked     string `json:"masked"`
}

type legacyKeyDiscoveryResponse struct {
	Findings      []legacyKeyFinding `json:"findings"`
	Total         int                `json:"total"`
	ProviderCount map[string]int     `json:"provider_count"`
	ScannedPaths  []string           `json:"scanned_paths"`
	Warnings      []string           `json:"warnings,omitempty"`
	GeneratedAt   time.Time          `json:"generated_at"`
}

type legacyKeyImportRequest struct {
	ConnectionID string   `json:"connection_id"`
	FindingIDs   []string `json:"finding_ids"`
}

type legacyKeyImportResponse struct {
	ImportedCount    int      `json:"imported_count"`
	ImportedVariable []string `json:"imported_variables"`
	ConnectionID     string   `json:"connection_id,omitempty"`
	BoundSecretKey   string   `json:"bound_secret_key,omitempty"`
	BoundVariable    string   `json:"bound_variable,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

type legacyKeyPurgeRequest struct {
	FindingIDs   []string `json:"finding_ids"`
	DryRun       bool     `json:"dry_run"`
	DeleteSkills bool     `json:"delete_skills"`
}

type legacyKeyPurgeAction struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
}

type legacyKeyPurgeResponse struct {
	DryRun        bool                   `json:"dry_run"`
	SelectedCount int                    `json:"selected_count"`
	PurgedCount   int                    `json:"purged_count"`
	Actions       []legacyKeyPurgeAction `json:"actions"`
	Warnings      []string               `json:"warnings,omitempty"`
}

type legacyKeyScanResult struct {
	Findings     []legacyKeyCandidate
	ScannedPaths []string
	Warnings     []string
	OpenClawHome string
	ConfigPath   string
	Workspace    string
	ConfigRoot   map[string]any
}

type legacyPathToken struct {
	Key     string
	Index   int
	IsIndex bool
}

type legacyKeyCandidate struct {
	Finding  legacyKeyFinding
	Value    string
	JSONPath []legacyPathToken
	EnvKey   string
}

func discoverLegacyOpenClawKeys() legacyKeyDiscoveryResponse {
	scan := scanLegacyOpenClawKeys()
	findings := make([]legacyKeyFinding, 0, len(scan.Findings))
	providerCount := map[string]int{}
	for _, finding := range scan.Findings {
		public := finding.Finding
		if strings.TrimSpace(public.Provider) == "" {
			public.Provider = "unknown"
		}
		providerCount[public.Provider] += 1
		findings = append(findings, public)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Provider != findings[j].Provider {
			return findings[i].Provider < findings[j].Provider
		}
		if findings[i].SourcePath != findings[j].SourcePath {
			return findings[i].SourcePath < findings[j].SourcePath
		}
		return findings[i].Location < findings[j].Location
	})
	return legacyKeyDiscoveryResponse{
		Findings:      findings,
		Total:         len(findings),
		ProviderCount: providerCount,
		ScannedPaths:  scan.ScannedPaths,
		Warnings:      scan.Warnings,
		GeneratedAt:   time.Now().UTC(),
	}
}

func importLegacyOpenClawKeys(connectorService *connectors.Service, request legacyKeyImportRequest) (legacyKeyImportResponse, error) {
	scan := scanLegacyOpenClawKeys()
	selected, err := selectLegacyCandidates(scan.Findings, request.FindingIDs)
	if err != nil {
		return legacyKeyImportResponse{}, err
	}
	if len(selected) == 0 {
		return legacyKeyImportResponse{}, errors.New("no legacy keys selected")
	}

	existingVars, err := connectorService.ListCredentialVariables()
	if err != nil {
		return legacyKeyImportResponse{}, fmt.Errorf("list credential variables: %w", err)
	}
	usedVariableKeys := map[string]struct{}{}
	for _, v := range existingVars {
		usedVariableKeys[strings.ToUpper(strings.TrimSpace(v.Key))] = struct{}{}
	}

	candidateVariableByID := map[string]string{}
	importedVariables := make([]string, 0, len(selected))
	for _, candidate := range selected {
		variable := chooseImportVariableKey(candidate, usedVariableKeys)
		if _, ok := candidateVariableByID[candidate.Finding.ID]; ok {
			continue
		}
		if _, err := connectorService.UpsertCredentialVariable(connectors.UpsertSharedCredentialVariableInput{
			Key:   variable,
			Value: candidate.Value,
		}); err != nil {
			return legacyKeyImportResponse{}, fmt.Errorf("store credential variable %q: %w", variable, err)
		}
		candidateVariableByID[candidate.Finding.ID] = variable
		importedVariables = append(importedVariables, variable)
		usedVariableKeys[strings.ToUpper(variable)] = struct{}{}
	}

	response := legacyKeyImportResponse{
		ImportedCount:    len(candidateVariableByID),
		ImportedVariable: importedVariables,
		Warnings:         scan.Warnings,
	}
	if strings.TrimSpace(request.ConnectionID) == "" || len(importedVariables) == 0 {
		return response, nil
	}

	connection, err := connectorService.GetConnection(strings.TrimSpace(request.ConnectionID))
	if err != nil {
		return legacyKeyImportResponse{}, fmt.Errorf("load connection %q: %w", request.ConnectionID, err)
	}
	selectedForConnection := chooseLegacyCandidateForConnection(selected, connection.ID)
	if selectedForConnection == nil {
		return response, nil
	}

	boundVariable, ok := candidateVariableByID[selectedForConnection.Finding.ID]
	if !ok {
		return response, nil
	}
	secretKey := chooseConnectionSecretKey(connection)
	if strings.TrimSpace(secretKey) == "" {
		return legacyKeyImportResponse{}, fmt.Errorf("connection %q has no secret key field", connection.ID)
	}
	if _, err := connectorService.RotateSecret(connection.ID, connectors.RotateSecretInput{
		Secrets: map[string]string{
			secretKey: fmt.Sprintf("{{%s}}", boundVariable),
		},
		RotatedBy:      "gateway-admin",
		RotationReason: "import openclaw legacy key",
	}); err != nil {
		return legacyKeyImportResponse{}, fmt.Errorf("bind credential variable to connection %q: %w", connection.ID, err)
	}
	if strings.TrimSpace(connection.AuthSecretKey) == "" {
		if _, err := connectorService.UpdateConnection(connection.ID, connectors.UpdateConnectionInput{
			AuthSecretKey: secretKey,
		}); err != nil {
			return legacyKeyImportResponse{}, fmt.Errorf("set connection auth_secret_key: %w", err)
		}
	}

	response.ConnectionID = connection.ID
	response.BoundSecretKey = secretKey
	response.BoundVariable = boundVariable
	return response, nil
}

func purgeLegacyOpenClawKeys(request legacyKeyPurgeRequest) (legacyKeyPurgeResponse, error) {
	scan := scanLegacyOpenClawKeys()
	selected, err := selectLegacyCandidates(scan.Findings, request.FindingIDs)
	if err != nil {
		return legacyKeyPurgeResponse{}, err
	}
	if len(selected) == 0 {
		return legacyKeyPurgeResponse{}, errors.New("no legacy keys selected")
	}

	response := legacyKeyPurgeResponse{
		DryRun:        request.DryRun,
		SelectedCount: len(selected),
		PurgedCount:   len(selected),
		Warnings:      scan.Warnings,
		Actions:       []legacyKeyPurgeAction{},
	}

	configChanged := false
	configKeyRemovals := 0
	if scan.ConfigRoot != nil {
		uniqueJSONPaths := map[string][]legacyPathToken{}
		for _, candidate := range selected {
			if candidate.Finding.SourceType != string(legacyKeySourceConfig) {
				continue
			}
			pathID := formatLegacyJSONPath(candidate.JSONPath)
			if _, exists := uniqueJSONPaths[pathID]; exists {
				continue
			}
			uniqueJSONPaths[pathID] = candidate.JSONPath
		}
		for _, pathTokens := range uniqueJSONPaths {
			if deleteLegacyJSONPath(scan.ConfigRoot, pathTokens) {
				configChanged = true
				configKeyRemovals += 1
				response.Actions = append(response.Actions, legacyKeyPurgeAction{
					Type:   "remove_config_key",
					Target: scan.ConfigPath,
					Detail: formatLegacyJSONPath(pathTokens),
				})
			}
		}
	}

	envKeysByFile := map[string]map[string]struct{}{}
	for _, candidate := range selected {
		if candidate.Finding.SourceType != string(legacyKeySourceDotEnv) {
			continue
		}
		if _, ok := envKeysByFile[candidate.Finding.SourcePath]; !ok {
			envKeysByFile[candidate.Finding.SourcePath] = map[string]struct{}{}
		}
		envKeysByFile[candidate.Finding.SourcePath][candidate.EnvKey] = struct{}{}
	}

	for envPath, keys := range envKeysByFile {
		removed, changed, err := removeDotEnvKeys(envPath, keys, request.DryRun)
		if err != nil {
			return legacyKeyPurgeResponse{}, err
		}
		if !changed {
			continue
		}
		response.Actions = append(response.Actions, legacyKeyPurgeAction{
			Type:   "remove_env_keys",
			Target: envPath,
			Detail: fmt.Sprintf("removed %d key(s)", removed),
		})
	}

	if request.DeleteSkills && scan.ConfigRoot != nil {
		providers := map[string]struct{}{}
		for _, candidate := range selected {
			provider := strings.TrimSpace(candidate.Finding.Provider)
			if provider == "" {
				continue
			}
			providers[provider] = struct{}{}
		}
		if len(providers) > 0 {
			removedSkillEntries := removeLegacySkillEntries(scan.ConfigRoot, providers)
			if len(removedSkillEntries) > 0 {
				configChanged = true
				for _, entry := range removedSkillEntries {
					response.Actions = append(response.Actions, legacyKeyPurgeAction{
						Type:   "remove_skill_entry",
						Target: scan.ConfigPath,
						Detail: entry,
					})
					for _, dir := range legacySkillDirs(scan.OpenClawHome, scan.Workspace, entry) {
						if strings.TrimSpace(dir) == "" {
							continue
						}
						if request.DryRun {
							if _, err := os.Stat(dir); err == nil {
								response.Actions = append(response.Actions, legacyKeyPurgeAction{
									Type:   "remove_skill_dir",
									Target: dir,
								})
							}
							continue
						}
						if _, err := os.Stat(dir); err == nil {
							if err := os.RemoveAll(dir); err != nil {
								return legacyKeyPurgeResponse{}, fmt.Errorf("remove skill directory %q: %w", dir, err)
							}
							response.Actions = append(response.Actions, legacyKeyPurgeAction{
								Type:   "remove_skill_dir",
								Target: dir,
							})
						}
					}
				}
			}
		}
	}

	if configChanged && scan.ConfigPath != "" {
		if request.DryRun {
			response.Actions = append(response.Actions, legacyKeyPurgeAction{
				Type:   "write_config",
				Target: scan.ConfigPath,
				Detail: fmt.Sprintf("remove %d key(s)", configKeyRemovals),
			})
		} else {
			if err := writeJSONFileWithBackup(scan.ConfigPath, scan.ConfigRoot); err != nil {
				return legacyKeyPurgeResponse{}, err
			}
			response.Actions = append(response.Actions, legacyKeyPurgeAction{
				Type:   "write_config",
				Target: scan.ConfigPath,
				Detail: fmt.Sprintf("removed %d key(s)", configKeyRemovals),
			})
		}
	}

	return response, nil
}

func selectLegacyCandidates(candidates []legacyKeyCandidate, ids []string) ([]legacyKeyCandidate, error) {
	if len(ids) == 0 {
		return candidates, nil
	}
	lookup := map[string]struct{}{}
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		lookup[trimmed] = struct{}{}
	}
	if len(lookup) == 0 {
		return nil, errors.New("finding_ids must include at least one id")
	}
	selected := make([]legacyKeyCandidate, 0, len(ids))
	for _, candidate := range candidates {
		if _, ok := lookup[candidate.Finding.ID]; ok {
			selected = append(selected, candidate)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("no matching legacy keys for finding_ids")
	}
	return selected, nil
}

func chooseLegacyCandidateForConnection(candidates []legacyKeyCandidate, connectionID string) *legacyKeyCandidate {
	connectionProvider := providerFromConnectionID(connectionID)
	for idx := range candidates {
		candidateProvider := strings.TrimSpace(candidates[idx].Finding.Provider)
		if candidateProvider != "" && candidateProvider == connectionProvider {
			return &candidates[idx]
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	return &candidates[0]
}

func chooseConnectionSecretKey(connection connectors.Connection) string {
	if key := strings.TrimSpace(connection.AuthSecretKey); key != "" {
		return key
	}
	if len(connection.CredentialKeys) > 0 {
		return strings.TrimSpace(connection.CredentialKeys[0])
	}
	return "api_key"
}

func chooseImportVariableKey(candidate legacyKeyCandidate, used map[string]struct{}) string {
	base := strings.TrimSpace(candidate.Finding.Variable)
	if !isValidCredentialVariableKey(base) {
		base = normalizeLegacyVariableKey(fmt.Sprintf("%s_%s", candidate.Finding.Provider, candidate.Finding.Field))
	}
	if !isValidCredentialVariableKey(base) {
		base = "SIGILUM_IMPORTED_KEY"
	}
	unique := base
	counter := 2
	for {
		_, exists := used[strings.ToUpper(unique)]
		if !exists {
			return unique
		}
		unique = fmt.Sprintf("%s_%d", base, counter)
		counter += 1
	}
}

func removeLegacySkillEntries(configRoot map[string]any, providers map[string]struct{}) []string {
	skills, ok := asMap(configRoot["skills"])
	if !ok {
		return nil
	}
	entries, ok := asMap(skills["entries"])
	if !ok {
		return nil
	}
	removed := make([]string, 0, 4)
	for entryName := range entries {
		if !shouldRemoveLegacySkill(entryName, providers) {
			continue
		}
		delete(entries, entryName)
		removed = append(removed, entryName)
	}
	sort.Strings(removed)
	return removed
}

func shouldRemoveLegacySkill(skillName string, providers map[string]struct{}) bool {
	normalized := strings.ToLower(strings.TrimSpace(skillName))
	if normalized == "" {
		return false
	}
	if normalized == "sigilum" || strings.HasPrefix(normalized, "sigilum-") {
		return false
	}
	for provider := range providers {
		if provider == "" {
			continue
		}
		if strings.Contains(normalized, provider) {
			return true
		}
	}
	return false
}

func legacySkillDirs(openClawHome string, workspace string, skillEntry string) []string {
	dirs := []string{}
	if trimmedHome := strings.TrimSpace(openClawHome); trimmedHome != "" {
		dirs = append(dirs, filepath.Join(trimmedHome, "skills", skillEntry))
	}
	if trimmedWorkspace := strings.TrimSpace(workspace); trimmedWorkspace != "" {
		dirs = append(dirs, filepath.Join(trimmedWorkspace, "skills", skillEntry))
	}
	return dirs
}

func removeDotEnvKeys(path string, removeKeys map[string]struct{}, dryRun bool) (removed int, changed bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read env file %q: %w", path, err)
	}
	lines := strings.Split(string(raw), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		key, ok := parseDotEnvLineKey(line)
		if ok {
			if _, shouldRemove := removeKeys[key]; shouldRemove {
				removed += 1
				changed = true
				continue
			}
		}
		filtered = append(filtered, line)
	}
	if !changed || dryRun {
		return removed, changed, nil
	}
	if err := backupFile(path); err != nil {
		return removed, changed, err
	}
	content := strings.Join(filtered, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return removed, changed, fmt.Errorf("write env file %q: %w", path, err)
	}
	return removed, changed, nil
}

func writeJSONFileWithBackup(path string, payload map[string]any) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("openclaw config path is required")
	}
	if err := backupFile(path); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode openclaw config: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return fmt.Errorf("write openclaw config %q: %w", path, err)
	}
	return nil
}

func backupFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read backup source %q: %w", path, err)
	}
	backupPath := fmt.Sprintf("%s.bak.sigilum-%s", path, time.Now().UTC().Format("20060102T150405"))
	if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
		return fmt.Errorf("write backup %q: %w", backupPath, err)
	}
	return nil
}

func deleteLegacyJSONPath(root map[string]any, path []legacyPathToken) bool {
	if len(path) == 0 {
		return false
	}
	var current any = root
	for idx, token := range path {
		last := idx == len(path)-1
		if token.IsIndex {
			array, ok := current.([]any)
			if !ok || token.Index < 0 || token.Index >= len(array) {
				return false
			}
			if last {
				array[token.Index] = nil
				return true
			}
			current = array[token.Index]
			continue
		}
		object, ok := asMap(current)
		if !ok {
			return false
		}
		if last {
			if _, exists := object[token.Key]; !exists {
				return false
			}
			delete(object, token.Key)
			return true
		}
		next, exists := object[token.Key]
		if !exists {
			return false
		}
		current = next
	}
	return false
}

func formatLegacyJSONPath(path []legacyPathToken) string {
	if len(path) == 0 {
		return "$"
	}
	var builder strings.Builder
	builder.WriteString("$")
	for _, token := range path {
		if token.IsIndex {
			builder.WriteString("[")
			builder.WriteString(fmt.Sprintf("%d", token.Index))
			builder.WriteString("]")
			continue
		}
		if token.Key == "" {
			continue
		}
		builder.WriteString(".")
		builder.WriteString(token.Key)
	}
	return builder.String()
}

func scanLegacyOpenClawKeys() legacyKeyScanResult {
	result := legacyKeyScanResult{
		Findings:     []legacyKeyCandidate{},
		ScannedPaths: []string{},
		Warnings:     []string{},
	}

	openClawHome := strings.TrimSpace(os.Getenv("OPENCLAW_HOME"))
	if openClawHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			openClawHome = filepath.Join(home, ".openclaw")
		}
	}
	configPath := strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH"))
	if configPath == "" && openClawHome != "" {
		configPath = filepath.Join(openClawHome, "openclaw.json")
	}
	result.OpenClawHome = openClawHome
	result.ConfigPath = configPath

	workspace := ""
	configRoot := map[string]any(nil)
	if configPath != "" {
		result.ScannedPaths = append(result.ScannedPaths, configPath)
		if raw, err := os.ReadFile(configPath); err == nil {
			parsed := map[string]any{}
			if err := json.Unmarshal(raw, &parsed); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to parse %s: %v", configPath, err))
			} else {
				configRoot = parsed
				workspace = extractOpenClawWorkspace(parsed)
				collectLegacyJSONCandidates(parsed, configPath, nil, "", &result.Findings)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to read %s: %v", configPath, err))
		}
	}
	result.ConfigRoot = configRoot
	result.Workspace = workspace

	envPaths := uniquePaths([]string{
		joinPathIfBase(openClawHome, ".env"),
		joinPathIfBase(openClawHome, ".env.local"),
		joinPathIfBase(openClawHome, "workspace", ".env"),
		joinPathIfBase(openClawHome, "workspace", ".env.local"),
		joinPathIfBase(workspace, ".env"),
		joinPathIfBase(workspace, ".env.local"),
	})
	for _, envPath := range envPaths {
		if strings.TrimSpace(envPath) == "" {
			continue
		}
		result.ScannedPaths = append(result.ScannedPaths, envPath)
		collectLegacyDotEnvCandidates(envPath, &result.Findings)
	}

	result.Findings = dedupeLegacyCandidates(result.Findings)
	return result
}

func dedupeLegacyCandidates(candidates []legacyKeyCandidate) []legacyKeyCandidate {
	if len(candidates) <= 1 {
		return candidates
	}
	seen := map[string]struct{}{}
	out := make([]legacyKeyCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Finding.ID == "" {
			continue
		}
		if _, ok := seen[candidate.Finding.ID]; ok {
			continue
		}
		seen[candidate.Finding.ID] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func collectLegacyDotEnvCandidates(path string, out *[]legacyKeyCandidate) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(raw), "\n")
	for lineNo, line := range lines {
		key, value, ok := parseDotEnvLine(line)
		if !ok {
			continue
		}
		provider := inferProviderFromEnvKey(key)
		if provider == "" {
			provider = inferProviderFromSource(path)
		}
		if !looksLikeLegacySecret(value) {
			continue
		}
		if !looksLikeLegacySecretKeyName(key) {
			continue
		}
		variable := normalizeLegacyVariableKey(key)
		location := fmt.Sprintf("%s:%d", filepath.Base(path), lineNo+1)
		finding := legacyKeyFinding{
			Provider:   provider,
			Field:      key,
			Variable:   variable,
			SourceType: string(legacyKeySourceDotEnv),
			SourcePath: path,
			Location:   location,
			Masked:     maskSecretValue(value),
		}
		finding.ID = legacyFindingID(finding)
		*out = append(*out, legacyKeyCandidate{
			Finding: finding,
			Value:   strings.TrimSpace(value),
			EnvKey:  strings.TrimSpace(key),
		})
	}
}

func parseDotEnvLine(line string) (key string, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	trimmed = strings.TrimPrefix(trimmed, "export ")
	equalIndex := strings.Index(trimmed, "=")
	if equalIndex <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trimmed[:equalIndex])
	if key == "" {
		return "", "", false
	}
	value = strings.TrimSpace(trimmed[equalIndex+1:])
	if value == "" {
		return "", "", false
	}
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && len(value) >= 2 {
		value = strings.Trim(value, `"`)
	} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") && len(value) >= 2 {
		value = strings.Trim(value, "'")
	} else {
		if commentIdx := strings.Index(value, " #"); commentIdx >= 0 {
			value = strings.TrimSpace(value[:commentIdx])
		}
	}
	return key, value, strings.TrimSpace(value) != ""
}

func parseDotEnvLineKey(line string) (string, bool) {
	key, _, ok := parseDotEnvLine(line)
	return key, ok
}

func collectLegacyJSONCandidates(node any, sourcePath string, path []legacyPathToken, providerHint string, out *[]legacyKeyCandidate) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			nextPath := append(pathClone(path), legacyPathToken{Key: key})
			nextProvider := providerHint
			if inferred := normalizeProviderToken(key); inferred != "" {
				nextProvider = inferred
			}
			if stringValue, ok := value.(string); ok {
				if !looksLikeLegacySecret(stringValue) {
					continue
				}
				if !looksLikeLegacySecretKeyName(key) && inferProviderFromEnvKey(key) == "" {
					continue
				}
				provider := nextProvider
				if provider == "" {
					provider = inferProviderFromEnvKey(key)
				}
				if provider == "" {
					provider = inferProviderFromSource(formatLegacyJSONPath(nextPath))
				}
				field := strings.TrimSpace(key)
				if field == "" {
					field = "api_key"
				}
				variable := normalizeLegacyVariableKey(key)
				if variable == "" || variable == "APIKEY" || variable == "TOKEN" || variable == "SECRET" {
					variable = normalizeLegacyVariableKey(fmt.Sprintf("%s_%s", provider, field))
				}
				finding := legacyKeyFinding{
					Provider:   provider,
					Field:      field,
					Variable:   variable,
					SourceType: string(legacyKeySourceConfig),
					SourcePath: sourcePath,
					Location:   formatLegacyJSONPath(nextPath),
					Masked:     maskSecretValue(stringValue),
				}
				finding.ID = legacyFindingID(finding)
				*out = append(*out, legacyKeyCandidate{
					Finding:  finding,
					Value:    strings.TrimSpace(stringValue),
					JSONPath: nextPath,
				})
				continue
			}
			collectLegacyJSONCandidates(value, sourcePath, nextPath, nextProvider, out)
		}
	case []any:
		for idx, value := range typed {
			nextPath := append(pathClone(path), legacyPathToken{IsIndex: true, Index: idx})
			collectLegacyJSONCandidates(value, sourcePath, nextPath, providerHint, out)
		}
	}
}

func pathClone(path []legacyPathToken) []legacyPathToken {
	if len(path) == 0 {
		return nil
	}
	cloned := make([]legacyPathToken, len(path))
	copy(cloned, path)
	return cloned
}

func extractOpenClawWorkspace(configRoot map[string]any) string {
	agents, ok := asMap(configRoot["agents"])
	if ok {
		defaults, ok := asMap(agents["defaults"])
		if ok {
			if workspace, ok := defaults["workspace"].(string); ok {
				return strings.TrimSpace(workspace)
			}
		}
	}
	defaults, ok := asMap(configRoot["defaults"])
	if ok {
		if workspace, ok := defaults["workspace"].(string); ok {
			return strings.TrimSpace(workspace)
		}
	}
	return ""
}

func asMap(value any) (map[string]any, bool) {
	if value == nil {
		return nil, false
	}
	cast, ok := value.(map[string]any)
	return cast, ok
}

func inferProviderFromSource(source string) string {
	tokens := splitLegacyTokens(source)
	for _, token := range tokens {
		if provider := normalizeProviderToken(token); provider != "" {
			return provider
		}
	}
	return ""
}

func inferProviderFromEnvKey(key string) string {
	tokens := strings.Split(strings.ToLower(strings.TrimSpace(key)), "_")
	for _, token := range tokens {
		if provider := normalizeProviderToken(token); provider != "" {
			return provider
		}
	}
	return ""
}

func providerFromConnectionID(connectionID string) string {
	trimmed := strings.ToLower(strings.TrimSpace(connectionID))
	trimmed = strings.TrimPrefix(trimmed, "sigilum-secure-")
	trimmed = strings.TrimSuffix(trimmed, "-mcp")
	if provider := normalizeProviderToken(trimmed); provider != "" {
		return provider
	}
	for _, token := range splitLegacyTokens(trimmed) {
		if provider := normalizeProviderToken(token); provider != "" {
			return provider
		}
	}
	return ""
}

func splitLegacyTokens(input string) []string {
	replacer := strings.NewReplacer(
		"/", " ",
		".", " ",
		"-", " ",
		"_", " ",
		"[", " ",
		"]", " ",
		"{", " ",
		"}", " ",
		":", " ",
	)
	cleaned := replacer.Replace(strings.ToLower(strings.TrimSpace(input)))
	parts := strings.Fields(cleaned)
	return parts
}

var legacyProviderAlias = map[string]string{
	"anthropic":   "anthropic",
	"claude":      "anthropic",
	"azure":       "azure",
	"cohere":      "cohere",
	"cerebras":    "cerebras",
	"deepseek":    "deepseek",
	"discord":     "discord",
	"fireworks":   "fireworks",
	"gemini":      "google",
	"google":      "google",
	"groq":        "groq",
	"hf":          "huggingface",
	"huggingface": "huggingface",
	"linear":      "linear",
	"mistral":     "mistral",
	"notion":      "notion",
	"openai":      "openai",
	"openrouter":  "openrouter",
	"perplexity":  "perplexity",
	"replicate":   "replicate",
	"serpapi":     "serpapi",
	"slack":       "slack",
	"together":    "together",
	"vertex":      "google",
	"voyage":      "voyage",
	"xai":         "xai",
}

func normalizeProviderToken(token string) string {
	trimmed := strings.ToLower(strings.TrimSpace(token))
	trimmed = strings.Trim(trimmed, "._- ")
	if trimmed == "" {
		return ""
	}
	if provider, ok := legacyProviderAlias[trimmed]; ok {
		return provider
	}
	return ""
}

func looksLikeLegacySecretKeyName(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") {
		return true
	}
	if strings.HasSuffix(lower, "_token") || strings.Contains(lower, "access_token") {
		return true
	}
	if strings.HasSuffix(lower, "_secret") || strings.Contains(lower, "client_secret") {
		return true
	}
	return false
}

func looksLikeLegacySecret(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		trimmed = strings.TrimSpace(trimmed[7:])
	}
	if trimmed == "" || len(trimmed) < 8 {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") {
		return false
	}
	if strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}") {
		return false
	}
	for _, marker := range []string{"your_api_key", "your-api-key", "placeholder", "changeme", "replace_me", "example", "sigilum-provider-proxy-key"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, prefix := range []string{"sk-", "xoxb-", "xoxp-", "xapp-", "ghp_", "pat_", "pk_live_", "sk_live_", "sk_test_", "aiza", "xai-"} {
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return true
		}
	}
	letters := 0
	digits := 0
	other := 0
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			letters += 1
		case r >= 'A' && r <= 'Z':
			letters += 1
		case r >= '0' && r <= '9':
			digits += 1
		case r == '-' || r == '_' || r == '.':
			other += 1
		case r == ' ' || r == '\t':
			return false
		default:
			other += 1
		}
	}
	if letters < 3 || digits < 2 {
		return false
	}
	return len(trimmed) >= 12 && (other >= 1 || len(trimmed) >= 20)
}

func maskSecretValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 8 {
		return strings.Repeat("*", len(trimmed))
	}
	return fmt.Sprintf("%s...%s", trimmed[:4], trimmed[len(trimmed)-4:])
}

func normalizeLegacyVariableKey(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(trimmed))
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 32)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			builder.WriteRune('_')
		default:
			builder.WriteRune('_')
		}
	}
	normalized := strings.Trim(builder.String(), "_")
	normalized = strings.ReplaceAll(normalized, "__", "_")
	normalized = strings.ReplaceAll(normalized, "__", "_")
	if normalized == "" {
		return ""
	}
	if !isValidCredentialVariableKey(normalized) {
		return ""
	}
	return normalized
}

func isValidCredentialVariableKey(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 || len(trimmed) > 128 {
		return false
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func legacyFindingID(finding legacyKeyFinding) string {
	raw := strings.Join([]string{
		finding.Provider,
		finding.Field,
		finding.SourceType,
		finding.SourcePath,
		finding.Location,
	}, "|")
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:12])
}

func uniquePaths(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func joinPathIfBase(base string, elems ...string) string {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		return ""
	}
	parts := append([]string{trimmed}, elems...)
	return filepath.Join(parts...)
}

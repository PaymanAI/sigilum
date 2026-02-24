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

	"sigilum.local/gateway/internal/catalog"
	"sigilum.local/gateway/internal/connectors"
)

type legacyKeySourceType string

const (
	legacyKeySourceConfig          legacyKeySourceType = "openclaw_config"
	legacyKeySourceDotEnv          legacyKeySourceType = "dotenv"
	legacyKeySourceRuntimeManifest legacyKeySourceType = "openclaw_runtime_manifest"
)

type legacyKeyFinding struct {
	ID                  string `json:"id"`
	Provider            string `json:"provider"`
	Field               string `json:"field"`
	Variable            string `json:"variable"`
	SourceType          string `json:"source_type"`
	SourcePath          string `json:"source_path"`
	Location            string `json:"location"`
	Masked              string `json:"masked"`
	AlreadySecured      bool   `json:"already_secured"`
	SecuredConnectionID string `json:"secured_connection_id,omitempty"`
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
	ImportedCount      int                       `json:"imported_count"`
	ImportedVariable   []string                  `json:"imported_variables"`
	ConnectionID       string                    `json:"connection_id,omitempty"`
	BoundSecretKey     string                    `json:"bound_secret_key,omitempty"`
	BoundVariable      string                    `json:"bound_variable,omitempty"`
	SecuredFindingIDs  []string                  `json:"secured_finding_ids,omitempty"`
	SecuredConnections []legacySecuredConnection `json:"secured_connections,omitempty"`
	SkippedFindings    []legacySkippedFinding    `json:"skipped_findings,omitempty"`
	Warnings           []string                  `json:"warnings,omitempty"`
}

type legacySecuredConnection struct {
	Provider       string   `json:"provider"`
	ConnectionID   string   `json:"connection_id"`
	ConnectionName string   `json:"connection_name"`
	TemplateKey    string   `json:"template_key,omitempty"`
	Created        bool     `json:"created"`
	ImportedCount  int      `json:"imported_count"`
	SecretKeys     []string `json:"secret_keys,omitempty"`
}

type legacySkippedFinding struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	Field      string `json:"field"`
	SourcePath string `json:"source_path"`
	Masked     string `json:"masked"`
	Reason     string `json:"reason"`
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

type runtimeLegacyCredentialReport struct {
	GeneratedAt string                        `json:"generated_at"`
	Findings    []runtimeLegacyCredentialItem `json:"findings"`
}

type runtimeLegacyCredentialItem struct {
	Provider   string `json:"provider"`
	Field      string `json:"field"`
	Variable   string `json:"variable"`
	Value      string `json:"value"`
	SourcePath string `json:"source_path"`
	Location   string `json:"location"`
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

type legacySecuredConnectionSecrets struct {
	Provider     string
	ConnectionID string
	SecretValues map[string]struct{}
}

func discoverLegacyOpenClawKeys(connectorService *connectors.Service) legacyKeyDiscoveryResponse {
	scan := scanLegacyOpenClawKeys()
	securedByProvider, securedAnyProvider, securedWarnings := discoverLegacySecuredConnections(connectorService)
	findings := make([]legacyKeyFinding, 0, len(scan.Findings))
	providerCount := map[string]int{}
	for _, finding := range scan.Findings {
		public := finding.Finding
		if strings.TrimSpace(public.Provider) == "" {
			public.Provider = "unknown"
		}
		if connectionID := findLegacySecuredConnectionID(finding, securedByProvider, securedAnyProvider); connectionID != "" {
			public.AlreadySecured = true
			public.SecuredConnectionID = connectionID
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
		Warnings:      append(scan.Warnings, securedWarnings...),
		GeneratedAt:   time.Now().UTC(),
	}
}

func importLegacyOpenClawKeys(connectorService *connectors.Service, catalogStore *catalog.Store, request legacyKeyImportRequest) (legacyKeyImportResponse, error) {
	scan := scanLegacyOpenClawKeys()
	selected, err := selectLegacyCandidates(scan.Findings, request.FindingIDs)
	if err != nil {
		return legacyKeyImportResponse{}, err
	}
	if len(selected) == 0 {
		return legacyKeyImportResponse{}, errors.New("no legacy keys selected")
	}
	sortLegacyCandidates(selected)

	response := legacyKeyImportResponse{
		ImportedCount:      0,
		ImportedVariable:   []string{},
		SecuredFindingIDs:  []string{},
		SecuredConnections: []legacySecuredConnection{},
		SkippedFindings:    []legacySkippedFinding{},
		Warnings:           scan.Warnings,
	}

	if connectionID := strings.TrimSpace(request.ConnectionID); connectionID != "" {
		connection, err := connectorService.GetConnection(connectionID)
		if err != nil {
			return legacyKeyImportResponse{}, fmt.Errorf("load connection %q: %w", request.ConnectionID, err)
		}
		selectedForConnection := chooseLegacyCandidateForConnection(selected, connection.ID)
		if selectedForConnection == nil {
			return response, nil
		}
		secretKey := chooseConnectionSecretKey(connection)
		if strings.TrimSpace(secretKey) == "" {
			return legacyKeyImportResponse{}, fmt.Errorf("connection %q has no secret key field", connection.ID)
		}
		if _, err := connectorService.RotateSecret(connection.ID, connectors.RotateSecretInput{
			Secrets: map[string]string{
				secretKey: selectedForConnection.Value,
			},
			RotatedBy:      "gateway-admin",
			RotationReason: "import openclaw legacy key",
		}); err != nil {
			if !isLegacyNoopRotateError(err) {
				return legacyKeyImportResponse{}, fmt.Errorf("set connection secret for %q: %w", connection.ID, err)
			}
			response.Warnings = append(response.Warnings, fmt.Sprintf("provider %q already secured; secret unchanged", connection.ID))
		}
		if strings.TrimSpace(connection.AuthSecretKey) == "" {
			if _, err := connectorService.UpdateConnection(connection.ID, connectors.UpdateConnectionInput{
				AuthSecretKey: secretKey,
			}); err != nil {
				return legacyKeyImportResponse{}, fmt.Errorf("set connection auth_secret_key: %w", err)
			}
		}

		provider := normalizeProviderToken(selectedForConnection.Finding.Provider)
		if provider == "" {
			provider = "unknown"
		}
		response.ConnectionID = connection.ID
		response.BoundSecretKey = secretKey
		response.SecuredFindingIDs = append(response.SecuredFindingIDs, selectedForConnection.Finding.ID)
		response.ImportedCount = 1
		response.SecuredConnections = append(response.SecuredConnections, legacySecuredConnection{
			Provider:       provider,
			ConnectionID:   connection.ID,
			ConnectionName: connection.Name,
			Created:        false,
			ImportedCount:  1,
			SecretKeys:     []string{secretKey},
		})
		return response, nil
	}

	templates, templateWarnings := loadLegacyImportTemplates(catalogStore)
	response.Warnings = append(response.Warnings, templateWarnings...)

	existingConnections, err := connectorService.ListConnections()
	if err != nil {
		return legacyKeyImportResponse{}, fmt.Errorf("list connections: %w", err)
	}
	usedConnectionIDs := map[string]struct{}{}
	existingByProvider := map[string][]connectors.Connection{}
	for _, existing := range existingConnections {
		usedConnectionIDs[existing.ID] = struct{}{}
		provider := providerFromConnectionID(existing.ID)
		if provider == "" {
			continue
		}
		existingByProvider[provider] = append(existingByProvider[provider], existing)
	}
	for provider := range existingByProvider {
		sort.Slice(existingByProvider[provider], func(i, j int) bool {
			return existingByProvider[provider][i].ID < existingByProvider[provider][j].ID
		})
	}

	candidatesByProvider := map[string][]legacyKeyCandidate{}
	for _, candidate := range selected {
		provider := normalizeProviderToken(candidate.Finding.Provider)
		if provider == "" {
			provider = "unknown"
		}
		candidatesByProvider[provider] = append(candidatesByProvider[provider], candidate)
	}
	providers := make([]string, 0, len(candidatesByProvider))
	for provider := range candidatesByProvider {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	securedFindingIDSet := map[string]struct{}{}
	for _, provider := range providers {
		providerCandidates := candidatesByProvider[provider]
		template, ok := selectLegacyTemplateForProvider(provider, templates)
		if !ok {
			for _, candidate := range providerCandidates {
				response.SkippedFindings = append(response.SkippedFindings, legacySkippedFinding{
					ID:         candidate.Finding.ID,
					Provider:   candidate.Finding.Provider,
					Field:      candidate.Finding.Field,
					SourcePath: candidate.Finding.SourcePath,
					Masked:     candidate.Finding.Masked,
					Reason:     "No Sigilum provider template matched this provider",
				})
			}
			continue
		}
		assignments := buildLegacyImportAssignments(providerCandidates, template)
		if len(assignments) == 0 {
			continue
		}

		providerExisting := existingByProvider[provider]
		existingIndex := 0
		for _, assignment := range assignments {
			if len(assignment.Secrets) == 0 {
				continue
			}
			authSecretKey := resolvedTemplateAuthSecretKey(template)
			if strings.TrimSpace(assignment.Secrets[authSecretKey]) == "" {
				if value, ok := firstLegacySecretValue(assignment.Secrets); ok {
					assignment.Secrets[authSecretKey] = value
				}
			}
			if strings.TrimSpace(assignment.Secrets[authSecretKey]) == "" {
				continue
			}

			if existingIndex < len(providerExisting) {
				existingConnection := providerExisting[existingIndex]
				existingIndex += 1
				connectionSecretKey := chooseConnectionSecretKey(existingConnection)
				if strings.TrimSpace(connectionSecretKey) == "" {
					connectionSecretKey = authSecretKey
				}
				if strings.TrimSpace(assignment.Secrets[connectionSecretKey]) == "" {
					assignment.Secrets[connectionSecretKey] = assignment.Secrets[authSecretKey]
				}
				if _, err := connectorService.RotateSecret(existingConnection.ID, connectors.RotateSecretInput{
					Secrets:        assignment.Secrets,
					RotatedBy:      "gateway-admin",
					RotationReason: "import openclaw legacy key",
				}); err != nil {
					if !isLegacyNoopRotateError(err) {
						return legacyKeyImportResponse{}, fmt.Errorf("update provider %q (%s): %w", existingConnection.ID, provider, err)
					}
					response.Warnings = append(response.Warnings, fmt.Sprintf("provider %q already secured; secret unchanged", existingConnection.ID))
				}
				if strings.TrimSpace(existingConnection.AuthSecretKey) == "" {
					if _, err := connectorService.UpdateConnection(existingConnection.ID, connectors.UpdateConnectionInput{
						AuthSecretKey: connectionSecretKey,
					}); err != nil {
						return legacyKeyImportResponse{}, fmt.Errorf("set auth_secret_key for %q: %w", existingConnection.ID, err)
					}
				}

				importedCount := 0
				for _, findingID := range assignment.FindingIDs {
					if _, exists := securedFindingIDSet[findingID]; exists {
						continue
					}
					securedFindingIDSet[findingID] = struct{}{}
					importedCount += 1
				}
				if importedCount == 0 {
					importedCount = 1
				}
				response.SecuredConnections = append(response.SecuredConnections, legacySecuredConnection{
					Provider:       provider,
					ConnectionID:   existingConnection.ID,
					ConnectionName: existingConnection.Name,
					TemplateKey:    template.Key,
					Created:        false,
					ImportedCount:  importedCount,
					SecretKeys:     sortedLegacySecretKeys(assignment.Secrets),
				})
				continue
			}

			connectionID := nextLegacyConnectionID(legacySecureConnectionBase(provider, template), usedConnectionIDs)
			createInput := legacyCreateConnectionInput(template, connectionID, assignment.Secrets)
			createdConnection, err := connectorService.CreateConnection(createInput)
			if err != nil {
				return legacyKeyImportResponse{}, fmt.Errorf("create provider connection %q (%s): %w", connectionID, provider, err)
			}
			usedConnectionIDs[connectionID] = struct{}{}

			importedCount := 0
			for _, findingID := range assignment.FindingIDs {
				if _, exists := securedFindingIDSet[findingID]; exists {
					continue
				}
				securedFindingIDSet[findingID] = struct{}{}
				importedCount += 1
			}
			if importedCount == 0 {
				importedCount = 1
			}
			response.SecuredConnections = append(response.SecuredConnections, legacySecuredConnection{
				Provider:       provider,
				ConnectionID:   createdConnection.ID,
				ConnectionName: createdConnection.Name,
				TemplateKey:    template.Key,
				Created:        true,
				ImportedCount:  importedCount,
				SecretKeys:     sortedLegacySecretKeys(assignment.Secrets),
			})
		}
	}

	for findingID := range securedFindingIDSet {
		response.SecuredFindingIDs = append(response.SecuredFindingIDs, findingID)
	}
	sort.Strings(response.SecuredFindingIDs)
	response.ImportedCount = len(response.SecuredFindingIDs)
	sort.Slice(response.SecuredConnections, func(i, j int) bool {
		if response.SecuredConnections[i].Provider != response.SecuredConnections[j].Provider {
			return response.SecuredConnections[i].Provider < response.SecuredConnections[j].Provider
		}
		return response.SecuredConnections[i].ConnectionID < response.SecuredConnections[j].ConnectionID
	})
	sort.Slice(response.SkippedFindings, func(i, j int) bool {
		if response.SkippedFindings[i].Provider != response.SkippedFindings[j].Provider {
			return response.SkippedFindings[i].Provider < response.SkippedFindings[j].Provider
		}
		if response.SkippedFindings[i].SourcePath != response.SkippedFindings[j].SourcePath {
			return response.SkippedFindings[i].SourcePath < response.SkippedFindings[j].SourcePath
		}
		return response.SkippedFindings[i].Field < response.SkippedFindings[j].Field
	})
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
		PurgedCount:   0,
		Warnings:      scan.Warnings,
		Actions:       []legacyKeyPurgeAction{},
	}
	runtimeSelectedCount := 0
	for _, candidate := range selected {
		if candidate.Finding.SourceType != string(legacyKeySourceRuntimeManifest) {
			continue
		}
		runtimeSelectedCount += 1
		response.Actions = append(response.Actions, legacyKeyPurgeAction{
			Type:   "manual_runtime_cleanup",
			Target: candidate.Finding.SourcePath,
			Detail: candidate.Finding.Location,
		})
	}
	if runtimeSelectedCount > 0 {
		response.Warnings = append(
			response.Warnings,
			fmt.Sprintf("%d runtime-discovered key(s) cannot be purged automatically; remove from runtime env or secret manager source", runtimeSelectedCount),
		)
	}

	configChanged := false
	configKeyRemovals := 0
	envKeyRemovals := 0
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
		envKeyRemovals += removed
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
	response.PurgedCount = configKeyRemovals + envKeyRemovals

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

func discoverLegacySecuredConnections(connectorService *connectors.Service) (map[string][]legacySecuredConnectionSecrets, []legacySecuredConnectionSecrets, []string) {
	if connectorService == nil {
		return map[string][]legacySecuredConnectionSecrets{}, nil, nil
	}

	connections, err := connectorService.ListConnections()
	if err != nil {
		return map[string][]legacySecuredConnectionSecrets{}, nil, []string{fmt.Sprintf("failed to inspect secured provider connections: %v", err)}
	}

	byProvider := map[string][]legacySecuredConnectionSecrets{}
	all := make([]legacySecuredConnectionSecrets, 0, len(connections))
	warnings := []string{}

	for _, connection := range connections {
		connectionID := strings.TrimSpace(connection.ID)
		if connectionID == "" {
			continue
		}
		provider := providerFromConnectionID(connectionID)
		if provider == "" {
			continue
		}
		resolved, err := connectorService.ResolveProxyConfig(connectionID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("could not inspect secured key for %q: %v", connectionID, err))
			continue
		}

		secretValues := map[string]struct{}{}
		for _, value := range resolved.Secrets {
			for _, variant := range legacySecretLookupVariants(value) {
				secretValues[variant] = struct{}{}
			}
		}
		for _, variant := range legacySecretLookupVariants(resolved.Secret) {
			secretValues[variant] = struct{}{}
		}
		if len(secretValues) == 0 {
			continue
		}

		entry := legacySecuredConnectionSecrets{
			Provider:     provider,
			ConnectionID: connectionID,
			SecretValues: secretValues,
		}
		byProvider[provider] = append(byProvider[provider], entry)
		all = append(all, entry)
	}

	for provider := range byProvider {
		sort.Slice(byProvider[provider], func(i, j int) bool {
			return byProvider[provider][i].ConnectionID < byProvider[provider][j].ConnectionID
		})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Provider != all[j].Provider {
			return all[i].Provider < all[j].Provider
		}
		return all[i].ConnectionID < all[j].ConnectionID
	})

	return byProvider, all, warnings
}

func findLegacySecuredConnectionID(
	candidate legacyKeyCandidate,
	byProvider map[string][]legacySecuredConnectionSecrets,
	anyProvider []legacySecuredConnectionSecrets,
) string {
	valueCandidates := legacySecretLookupVariants(candidate.Value)
	if len(valueCandidates) == 0 {
		return ""
	}
	provider := normalizeProviderToken(candidate.Finding.Provider)
	if provider != "" {
		return findLegacySecuredConnectionByProvider(valueCandidates, byProvider[provider])
	}
	return findLegacySecuredConnectionByProvider(valueCandidates, anyProvider)
}

func findLegacySecuredConnectionByProvider(valueCandidates []string, entries []legacySecuredConnectionSecrets) string {
	for _, entry := range entries {
		for _, candidate := range valueCandidates {
			if _, ok := entry.SecretValues[candidate]; ok {
				return entry.ConnectionID
			}
		}
	}
	return ""
}

func legacySecretLookupVariants(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	variants := []string{trimmed}
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		if stripped := strings.TrimSpace(trimmed[7:]); stripped != "" {
			variants = append(variants, stripped)
		}
	}
	return dedupeLegacyStringList(variants)
}

func isLegacyNoopRotateError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return message == "secrets are required"
}

type legacyImportAssignment struct {
	Secrets    map[string]string
	FindingIDs []string
}

func sortLegacyCandidates(candidates []legacyKeyCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Finding.Provider != candidates[j].Finding.Provider {
			return candidates[i].Finding.Provider < candidates[j].Finding.Provider
		}
		if candidates[i].Finding.SourcePath != candidates[j].Finding.SourcePath {
			return candidates[i].Finding.SourcePath < candidates[j].Finding.SourcePath
		}
		if candidates[i].Finding.Location != candidates[j].Finding.Location {
			return candidates[i].Finding.Location < candidates[j].Finding.Location
		}
		return candidates[i].Finding.Field < candidates[j].Finding.Field
	})
}

func loadLegacyImportTemplates(catalogStore *catalog.Store) ([]catalog.ServiceTemplate, []string) {
	warnings := []string{}
	if catalogStore == nil {
		defaultCatalog := catalog.DefaultCatalog()
		return defaultCatalog.Services, warnings
	}
	loaded, err := catalogStore.Load()
	if err != nil {
		defaultCatalog := catalog.DefaultCatalog()
		warnings = append(warnings, fmt.Sprintf("failed to load service catalog: %v (using default templates)", err))
		return defaultCatalog.Services, warnings
	}
	return loaded.Services, warnings
}

func selectLegacyTemplateForProvider(provider string, templates []catalog.ServiceTemplate) (catalog.ServiceTemplate, bool) {
	if len(templates) == 0 {
		return catalog.ServiceTemplate{}, false
	}
	aliases := legacyProviderTemplateAliases(provider)
	best := -1
	bestScore := -1
	for idx, template := range templates {
		score := 0
		templateKey := strings.ToLower(strings.TrimSpace(template.Key))
		connectionID := strings.ToLower(strings.TrimSpace(template.ConnectionID))
		label := strings.ToLower(strings.TrimSpace(template.Label))
		for _, alias := range aliases {
			if alias == "" {
				continue
			}
			if templateKey == alias {
				score += 100
			}
			if strings.Contains(connectionID, alias) {
				score += 60
			}
			if strings.Contains(label, alias) {
				score += 40
			}
		}
		if score == 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(template.Protocol)) == "http" || strings.TrimSpace(template.Protocol) == "" {
			score += 10
		}
		if score > bestScore {
			bestScore = score
			best = idx
		}
	}
	if best < 0 {
		return catalog.ServiceTemplate{}, false
	}
	return templates[best], true
}

func legacyProviderTemplateAliases(provider string) []string {
	base := normalizeProviderToken(provider)
	if base == "" {
		base = strings.ToLower(strings.TrimSpace(provider))
	}
	aliases := []string{base}
	switch base {
	case "anthropic":
		aliases = append(aliases, "claude")
	case "google":
		aliases = append(aliases, "gemini")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		trimmed := strings.TrimSpace(strings.ToLower(alias))
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

func buildLegacyImportAssignments(candidates []legacyKeyCandidate, template catalog.ServiceTemplate) []legacyImportAssignment {
	if len(candidates) == 0 {
		return nil
	}
	authSecretKey := resolvedTemplateAuthSecretKey(template)
	grouped := map[string][]legacyKeyCandidate{}
	for _, candidate := range candidates {
		grouped[legacyImportGroupKey(candidate)] = append(grouped[legacyImportGroupKey(candidate)], candidate)
	}
	groupKeys := make([]string, 0, len(grouped))
	for key := range grouped {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)

	assignments := make([]legacyImportAssignment, 0, len(groupKeys))
	for _, groupKey := range groupKeys {
		groupCandidates := grouped[groupKey]
		sortLegacyCandidates(groupCandidates)

		extraSecrets := map[string]string{}
		extraIDs := []string{}
		primaryCandidates := []legacyKeyCandidate{}
		for _, candidate := range groupCandidates {
			fieldKey := matchLegacyCandidateToTemplateField(candidate, template)
			if strings.TrimSpace(fieldKey) == "" {
				fieldKey = authSecretKey
			}
			if fieldKey == authSecretKey {
				primaryCandidates = append(primaryCandidates, candidate)
				continue
			}
			if strings.TrimSpace(extraSecrets[fieldKey]) != "" {
				continue
			}
			extraSecrets[fieldKey] = candidate.Value
			extraIDs = append(extraIDs, candidate.Finding.ID)
		}
		if len(primaryCandidates) == 0 && len(groupCandidates) > 0 {
			primaryCandidates = append(primaryCandidates, groupCandidates[0])
		}
		for _, primary := range primaryCandidates {
			secrets := map[string]string{}
			for key, value := range extraSecrets {
				secrets[key] = value
			}
			secrets[authSecretKey] = primary.Value
			findingIDs := append([]string{}, extraIDs...)
			findingIDs = append(findingIDs, primary.Finding.ID)
			findingIDs = dedupeLegacyStringList(findingIDs)
			assignments = append(assignments, legacyImportAssignment{
				Secrets:    secrets,
				FindingIDs: findingIDs,
			})
		}
	}
	return assignments
}

func legacyImportGroupKey(candidate legacyKeyCandidate) string {
	sourceType := strings.TrimSpace(candidate.Finding.SourceType)
	scope := strings.TrimSpace(candidate.Finding.SourcePath)
	switch sourceType {
	case string(legacyKeySourceConfig):
		location := strings.TrimSpace(candidate.Finding.Location)
		if idx := strings.LastIndex(location, "."); idx > 0 {
			location = location[:idx]
		}
		if location != "" {
			scope = location
		}
	case string(legacyKeySourceDotEnv):
		// Group dotenv keys by file path so provider keys from the same file can be secured together.
	case string(legacyKeySourceRuntimeManifest):
		// Runtime report keys are grouped per source path.
	default:
		location := strings.TrimSpace(candidate.Finding.Location)
		if location != "" {
			scope = location
		}
	}
	return fmt.Sprintf("%s|%s", sourceType, scope)
}

func matchLegacyCandidateToTemplateField(candidate legacyKeyCandidate, template catalog.ServiceTemplate) string {
	authSecretKey := resolvedTemplateAuthSecretKey(template)
	if len(template.CredentialFields) == 0 {
		return authSecretKey
	}
	candidateField := normalizeLegacyFieldToken(candidate.Finding.Field)
	candidateVariable := normalizeLegacyFieldToken(candidate.Finding.Variable)
	bestField := ""
	bestScore := -1
	for _, field := range template.CredentialFields {
		fieldKey := strings.TrimSpace(field.Key)
		if fieldKey == "" {
			continue
		}
		normalizedField := normalizeLegacyFieldToken(fieldKey)
		score := 0
		if candidateField != "" && normalizedField == candidateField {
			score += 100
		}
		if candidateVariable != "" && normalizedField == candidateVariable {
			score += 95
		}
		if candidateField != "" && (strings.Contains(candidateField, normalizedField) || strings.Contains(normalizedField, candidateField)) {
			score += 70
		}
		if candidateVariable != "" && (strings.Contains(candidateVariable, normalizedField) || strings.Contains(normalizedField, candidateVariable)) {
			score += 60
		}
		candidateBucket := legacyFieldBucket(candidateField)
		fieldBucket := legacyFieldBucket(normalizedField)
		if candidateBucket != "" && candidateBucket == fieldBucket {
			score += 35
		}
		if fieldKey == authSecretKey && candidateBucket != "" {
			score += 10
		}
		if score > bestScore {
			bestScore = score
			bestField = fieldKey
		}
	}
	if strings.TrimSpace(bestField) == "" {
		return authSecretKey
	}
	return bestField
}

func normalizeLegacyFieldToken(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(trimmed))
	lastUnderscore := false
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteRune('_')
			lastUnderscore = true
		}
	}
	normalized := strings.Trim(builder.String(), "_")
	normalized = strings.ReplaceAll(normalized, "__", "_")
	return normalized
}

func legacyFieldBucket(field string) string {
	switch {
	case strings.Contains(field, "bot_token"):
		return "bot_token"
	case strings.Contains(field, "app_token"):
		return "app_token"
	case strings.Contains(field, "access_token"):
		return "access_token"
	case strings.Contains(field, "api_key") || strings.Contains(field, "apikey"):
		return "api_key"
	case strings.Contains(field, "client_secret"):
		return "client_secret"
	case strings.Contains(field, "secret"):
		return "secret"
	case strings.Contains(field, "token"):
		return "token"
	default:
		return ""
	}
}

func resolvedTemplateAuthSecretKey(template catalog.ServiceTemplate) string {
	if key := strings.TrimSpace(template.AuthSecretKey); key != "" {
		return key
	}
	for _, field := range template.CredentialFields {
		if key := strings.TrimSpace(field.Key); key != "" {
			return key
		}
	}
	return "api_key"
}

func firstLegacySecretValue(secrets map[string]string) (string, bool) {
	keys := sortedLegacySecretKeys(secrets)
	for _, key := range keys {
		value := strings.TrimSpace(secrets[key])
		if value != "" {
			return value, true
		}
	}
	return "", false
}

func sortedLegacySecretKeys(secrets map[string]string) []string {
	if len(secrets) == 0 {
		return nil
	}
	keys := make([]string, 0, len(secrets))
	for key, value := range secrets {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func dedupeLegacyStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func legacySecureConnectionBase(provider string, template catalog.ServiceTemplate) string {
	base := normalizeLegacyConnectionSlug(provider)
	if base == "" {
		base = normalizeLegacyConnectionSlug(template.Key)
	}
	if base == "" {
		base = normalizeLegacyConnectionSlug(template.ConnectionID)
	}
	if base == "" {
		base = "provider"
	}
	if strings.HasPrefix(base, "sigilum-secure-") {
		return base
	}
	return "sigilum-secure-" + base
}

func normalizeLegacyConnectionSlug(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(trimmed))
	lastHyphen := false
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen {
			builder.WriteRune('-')
			lastHyphen = true
		}
	}
	normalized := strings.Trim(builder.String(), "-")
	normalized = strings.ReplaceAll(normalized, "--", "-")
	return normalized
}

func nextLegacyConnectionID(base string, used map[string]struct{}) string {
	normalizedBase := normalizeLegacyConnectionSlug(base)
	if normalizedBase == "" {
		normalizedBase = "sigilum-secure-provider"
	}
	if _, exists := used[normalizedBase]; !exists {
		return normalizedBase
	}
	index := 2
	for {
		candidate := fmt.Sprintf("%s-%d", normalizedBase, index)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
		index += 1
	}
}

func legacyCreateConnectionInput(template catalog.ServiceTemplate, connectionID string, secrets map[string]string) connectors.CreateConnectionInput {
	protocol := strings.TrimSpace(template.Protocol)
	baseURL := strings.TrimSpace(template.BaseURL)
	if strings.ToLower(protocol) == "mcp" && strings.TrimSpace(template.MCPBaseURL) != "" {
		baseURL = strings.TrimSpace(template.MCPBaseURL)
	}
	name := strings.TrimSpace(template.Label)
	if name == "" {
		name = connectionID
	}
	if !strings.EqualFold(connectionID, normalizeLegacyConnectionSlug(template.ConnectionID)) {
		name = fmt.Sprintf("%s (%s)", name, connectionID)
	}
	return connectors.CreateConnectionInput{
		ID:                     connectionID,
		Name:                   name,
		Protocol:               protocol,
		BaseURL:                baseURL,
		PathPrefix:             strings.TrimSpace(template.PathPrefix),
		AuthMode:               strings.TrimSpace(template.AuthMode),
		AuthHeaderName:         strings.TrimSpace(template.AuthHeaderName),
		AuthPrefix:             template.AuthPrefix,
		AuthSecretKey:          resolvedTemplateAuthSecretKey(template),
		Secrets:                secrets,
		RotationIntervalDays:   90,
		MCPTransport:           strings.TrimSpace(template.MCPTransport),
		MCPEndpoint:            strings.TrimSpace(template.MCPEndpoint),
		MCPToolAllowlist:       append([]string{}, template.MCPToolAllowlist...),
		MCPToolDenylist:        append([]string{}, template.MCPToolDenylist...),
		MCPMaxToolsExposed:     template.MCPMaxToolsExposed,
		MCPSubjectToolPolicies: mapCatalogSubjectPolicies(template.MCPSubjectToolPolicies),
	}
}

func mapCatalogSubjectPolicies(policies map[string]catalog.MCPToolPolicy) map[string]connectors.MCPToolPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]connectors.MCPToolPolicy, len(policies))
	for subject, policy := range policies {
		trimmedSubject := strings.TrimSpace(subject)
		if trimmedSubject == "" {
			continue
		}
		out[trimmedSubject] = connectors.MCPToolPolicy{
			Allowlist:       append([]string{}, policy.Allowlist...),
			Denylist:        append([]string{}, policy.Denylist...),
			MaxToolsExposed: policy.MaxToolsExposed,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

	for _, reportPath := range runtimeLegacyReportPaths(openClawHome, workspace) {
		if strings.TrimSpace(reportPath) == "" {
			continue
		}
		result.ScannedPaths = append(result.ScannedPaths, reportPath)
		collectRuntimeLegacyReportCandidates(reportPath, &result.Findings, &result.Warnings)
	}

	result.Findings = dedupeLegacyCandidates(result.Findings)
	return result
}

func dedupeLegacyCandidates(candidates []legacyKeyCandidate) []legacyKeyCandidate {
	if len(candidates) <= 1 {
		return candidates
	}
	seenIDs := map[string]struct{}{}
	seenValueSignatures := map[string]struct{}{}
	out := make([]legacyKeyCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Finding.ID == "" {
			continue
		}
		if _, ok := seenIDs[candidate.Finding.ID]; ok {
			continue
		}
		seenIDs[candidate.Finding.ID] = struct{}{}
		signature := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(candidate.Finding.Provider)),
			strings.ToUpper(strings.TrimSpace(candidate.Finding.Field)),
			strings.TrimSpace(candidate.Value),
		}, "|")
		if signature != "||" {
			if _, ok := seenValueSignatures[signature]; ok {
				continue
			}
			seenValueSignatures[signature] = struct{}{}
		}
		out = append(out, candidate)
	}
	return out
}

func runtimeLegacyReportPaths(openClawHome string, workspace string) []string {
	override := strings.TrimSpace(os.Getenv("OPENCLAW_LEGACY_RUNTIME_REPORT_PATH"))
	if override != "" {
		return []string{override}
	}
	return uniquePaths([]string{
		joinPathIfBase(openClawHome, ".sigilum", "legacy-runtime-credentials.json"),
		joinPathIfBase(workspace, ".sigilum", "legacy-runtime-credentials.json"),
	})
}

func collectRuntimeLegacyReportCandidates(path string, out *[]legacyKeyCandidate, warnings *[]string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			*warnings = append(*warnings, fmt.Sprintf("Failed to read runtime credential report %s: %v", path, err))
		}
		return
	}
	report := runtimeLegacyCredentialReport{}
	if err := json.Unmarshal(raw, &report); err != nil {
		*warnings = append(*warnings, fmt.Sprintf("Failed to parse runtime credential report %s: %v", path, err))
		return
	}
	for idx, finding := range report.Findings {
		value := strings.TrimSpace(finding.Value)
		field := strings.TrimSpace(finding.Field)
		if !looksLikeLegacySecret(value) {
			continue
		}
		if !looksLikeLegacySecretKeyName(field) && inferProviderFromEnvKey(field) == "" {
			continue
		}
		provider := strings.TrimSpace(finding.Provider)
		if provider == "" {
			provider = inferProviderFromEnvKey(field)
		}
		if provider == "" {
			provider = inferProviderFromSource(path)
		}
		provider = normalizeProviderToken(provider)
		if provider == "" {
			provider = "unknown"
		}
		variable := normalizeLegacyVariableKey(finding.Variable)
		if variable == "" {
			variable = normalizeLegacyVariableKey(field)
		}
		if variable == "" {
			variable = normalizeLegacyVariableKey(fmt.Sprintf("%s_%s", provider, field))
		}
		if variable == "" {
			variable = "SIGILUM_IMPORTED_KEY"
		}
		location := strings.TrimSpace(finding.Location)
		if location == "" {
			location = fmt.Sprintf("runtime_report[%d]", idx)
		}
		public := legacyKeyFinding{
			Provider:   provider,
			Field:      field,
			Variable:   variable,
			SourceType: string(legacyKeySourceRuntimeManifest),
			SourcePath: path,
			Location:   location,
			Masked:     maskSecretValue(value),
		}
		public.ID = legacyFindingID(public)
		*out = append(*out, legacyKeyCandidate{
			Finding: public,
			Value:   value,
		})
	}
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

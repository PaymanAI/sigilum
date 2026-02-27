package main

import (
	"os"
	"path/filepath"
	"strings"
)

func resolveServiceAPIKey(connectionID string, defaultValue string, sigilumHomeDir string) string {
	if scoped := strings.TrimSpace(os.Getenv("SIGILUM_SERVICE_API_KEY_" + serviceAPIKeyEnvSuffix(connectionID))); scoped != "" {
		return scoped
	}
	if !isSafeServiceKeyID(connectionID) {
		if fallback := strings.TrimSpace(defaultValue); fallback != "" {
			return fallback
		}
		return ""
	}

	for _, homeDir := range candidateServiceKeyHomes(sigilumHomeDir) {
		raw, err := os.ReadFile(filepath.Join(homeDir, "service-api-key-"+connectionID))
		if err != nil {
			continue
		}
		key := strings.TrimSpace(string(raw))
		if key != "" {
			return key
		}
	}
	if fallback := strings.TrimSpace(defaultValue); fallback != "" {
		return fallback
	}
	return ""
}

func candidateServiceKeyHomes(explicitHome string) []string {
	candidates := []string{}
	if value := strings.TrimSpace(explicitHome); value != "" {
		candidates = append(candidates, value)
	}
	if value := strings.TrimSpace(os.Getenv("SIGILUM_HOME")); value != "" {
		candidates = append(candidates, value)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		candidates = append(candidates, filepath.Join(home, ".sigilum-workspace"))
		candidates = append(candidates, filepath.Join(home, ".sigilum"))
		candidates = append(candidates, filepath.Join(home, ".openclaw", "workspace", ".sigilum"))
		candidates = append(candidates, filepath.Join(home, ".openclaw", ".sigilum"))
	}

	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	return deduped
}

func serviceAPIKeyEnvSuffix(connectionID string) string {
	value := strings.TrimSpace(connectionID)
	if value == "" {
		return "DEFAULT"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 32)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	suffix := strings.Trim(builder.String(), "_")
	if suffix == "" {
		return "DEFAULT"
	}
	return suffix
}

func isSafeServiceKeyID(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 3 || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		ch := v[i]
		isLower := ch >= 'a' && ch <= 'z'
		isDigit := ch >= '0' && ch <= '9'
		isHyphen := ch == '-'
		if !isLower && !isDigit && !isHyphen {
			return false
		}
		if (i == 0 || i == len(v)-1) && !isLower && !isDigit {
			return false
		}
	}
	return true
}

func truncateKeyPrefix(key string, maxLen int) string {
	if key == "" {
		return ""
	}
	if len(key) <= maxLen {
		return key[:len(key)/2] + "..."
	}
	return key[:maxLen] + "..."
}

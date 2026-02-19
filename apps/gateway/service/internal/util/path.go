package util

import "strings"

func JoinPath(paths ...string) string {
	parts := make([]string, 0, len(paths))
	for _, pathPart := range paths {
		trimmed := strings.TrimSpace(pathPart)
		if trimmed == "" {
			continue
		}
		cleaned := strings.Trim(trimmed, "/")
		if cleaned == "" {
			continue
		}
		parts = append(parts, cleaned)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

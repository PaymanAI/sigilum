package util

import "strings"

func CompactMessage(value string, maxLen int) string {
	compact := strings.Join(strings.Fields(value), " ")
	if compact == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 240
	}
	if len(compact) <= maxLen {
		return compact
	}
	return compact[:maxLen] + "..."
}

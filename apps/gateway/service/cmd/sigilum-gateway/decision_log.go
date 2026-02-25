package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

var decisionLogRedactedKeyFragments = []string{
	"token",
	"secret",
	"authorization",
	"cookie",
	"password",
	"private",
	"signature",
	"cert",
	"api_key",
}

var decisionLogHashedKeyFragments = []string{
	"namespace",
	"public_key",
	"agent_key",
	"key_id",
	"claim_id",
}

func logGatewayDecisionIf(enabled bool, event string, fields map[string]any) {
	if !enabled {
		return
	}
	logGatewayDecision(event, fields)
}

func logGatewayDecision(event string, fields map[string]any) {
	payload := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"component": "gateway",
		"kind":      "decision",
		"event":     strings.TrimSpace(event),
	}

	for key, value := range fields {
		normalizedKey := strings.TrimSpace(key)
		if normalizedKey == "" {
			continue
		}
		payload[normalizedKey] = sanitizeDecisionValue(normalizedKey, value)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("gateway decision log marshal failed event=%s err=%v", strings.TrimSpace(event), err)
		return
	}
	log.Print(string(encoded))
}

func sanitizeDecisionValue(key string, value any) any {
	return sanitizeDecisionValueDepth(key, value, 0)
}

func sanitizeDecisionValueDepth(key string, value any, depth int) any {
	if depth > 4 {
		return "[truncated]"
	}

	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			out[childKey] = sanitizeDecisionValueDepth(childKey, childValue, depth+1)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			out[childKey] = sanitizeDecisionValueDepth(childKey, childValue, depth+1)
		}
		return out
	case map[string][]string:
		out := make(map[string]any, len(typed))
		for childKey, childValues := range typed {
			out[childKey] = sanitizeDecisionValueDepth(childKey, childValues, depth+1)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, childValue := range typed {
			out = append(out, sanitizeDecisionValueDepth(key, childValue, depth+1))
		}
		return out
	case []string:
		out := make([]any, 0, len(typed))
		for _, childValue := range typed {
			out = append(out, sanitizeDecisionValueDepth(key, childValue, depth+1))
		}
		return out
	case string:
		return sanitizeDecisionString(key, typed)
	case bool:
		return typed
	case int:
		return typed
	case int8:
		return typed
	case int16:
		return typed
	case int32:
		return typed
	case int64:
		return typed
	case uint:
		return typed
	case uint8:
		return typed
	case uint16:
		return typed
	case uint32:
		return typed
	case uint64:
		return typed
	case float32:
		return typed
	case float64:
		return typed
	case time.Duration:
		return typed.Milliseconds()
	case error:
		return sanitizeDecisionString(key, typed.Error())
	case fmt.Stringer:
		return sanitizeDecisionString(key, typed.String())
	default:
		return sanitizeDecisionString(key, fmt.Sprintf("%v", value))
	}
}

func sanitizeDecisionString(key string, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	normalizedKey := strings.ToLower(strings.TrimSpace(key))

	if strings.Contains(normalizedKey, "ip") {
		return maskDecisionIP(trimmed)
	}
	if hasKeyFragment(normalizedKey, decisionLogRedactedKeyFragments) {
		return "[redacted]"
	}
	if hasKeyFragment(normalizedKey, decisionLogHashedKeyFragments) {
		return fingerprintDecisionValue(trimmed)
	}
	if len(trimmed) > 256 {
		return trimmed[:256] + "...(truncated)"
	}
	return trimmed
}

func constructDID(namespace, service, agent, subject string) string {
	namespace = strings.TrimSpace(namespace)
	service = strings.TrimSpace(service)
	agent = strings.TrimSpace(agent)
	if agent == "" {
		agent = "unknown-agent"
	}
	did := "did:sigilum:" + namespace + ":" + service + "#" + agent
	subject = strings.TrimSpace(subject)
	if subject != "" && subject != namespace {
		did += "#" + subject
	}
	return did
}

func didAgentFragment(publicKey string) string {
	fragment := strings.TrimSpace(publicKey)
	fragment = strings.TrimPrefix(fragment, "ed25519:")
	if len(fragment) > 24 {
		fragment = fragment[:12] + "-" + fragment[len(fragment)-8:]
	}
	fragment = sanitizeDIDFragment(fragment)
	if fragment == "" {
		return "unknown-agent"
	}
	return fragment
}

func sanitizeDIDFragment(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	var out strings.Builder
	lastDash := false
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		isAlpha := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
		isDigit := ch >= '0' && ch <= '9'
		switch {
		case isAlpha || isDigit || ch == '.' || ch == '_' || ch == '-':
			out.WriteByte(ch)
			lastDash = ch == '-'
		default:
			if !lastDash {
				out.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(out.String(), "-")
}

func hasKeyFragment(key string, fragments []string) bool {
	for _, fragment := range fragments {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func fingerprintDecisionValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

func maskDecisionIP(raw string) string {
	host := strings.TrimSpace(raw)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fingerprintDecisionValue(raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}

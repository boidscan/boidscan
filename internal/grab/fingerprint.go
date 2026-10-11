package grab

import (
	"encoding/json"
	"strings"
)

// Fingerprint identifies the server behind a result: its TLS leaf certificate
// or SSH host key. Firewalls and outages do not change it, so a different
// fingerprint at the same address means a different server or a false report.
func Fingerprint(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return strings.ToLower(findFingerprint(v))
}

func findFingerprint(v any) string {
	switch t := v.(type) {
	case map[string]any:
		if sc, ok := t["server_certificates"].(map[string]any); ok {
			if c, ok := sc["certificate"].(map[string]any); ok {
				if p, ok := c["parsed"].(map[string]any); ok {
					if fp, ok := p["fingerprint_sha256"].(string); ok {
						return fp
					}
				}
			}
		}
		if k, ok := t["server_host_key"].(map[string]any); ok {
			if fp, ok := k["fingerprint_sha256"].(string); ok {
				return fp
			}
		}
		for _, child := range t {
			if fp := findFingerprint(child); fp != "" {
				return fp
			}
		}
	case []any:
		for _, child := range t {
			if fp := findFingerprint(child); fp != "" {
				return fp
			}
		}
	}
	return ""
}

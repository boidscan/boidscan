package store

import (
	"encoding/json"
	"slices"
	"strings"
)

// CertInfo finds the leaf certificate anywhere in a zgrab2 result (HTTPS,
// STARTTLS and TLS-wrapped modules all nest it differently) and returns its
// SHA-256 fingerprint and lower-cased names.
func CertInfo(raw json.RawMessage) (string, []string) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", nil
	}
	parsed := findLeaf(v)
	if parsed == nil {
		return "", nil
	}
	sha, _ := parsed["fingerprint_sha256"].(string)
	var names []string
	if subj, ok := parsed["subject"].(map[string]any); ok {
		names = appendStrings(names, subj["common_name"])
	}
	if ext, ok := parsed["extensions"].(map[string]any); ok {
		if san, ok := ext["subject_alt_name"].(map[string]any); ok {
			names = appendStrings(names, san["dns_names"])
		}
	}
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	slices.Sort(names)
	return strings.ToLower(sha), slices.Compact(names)
}

func findLeaf(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		if sc, ok := t["server_certificates"].(map[string]any); ok {
			if c, ok := sc["certificate"].(map[string]any); ok {
				if p, ok := c["parsed"].(map[string]any); ok {
					return p
				}
			}
		}
		for _, child := range t {
			if p := findLeaf(child); p != nil {
				return p
			}
		}
	case []any:
		for _, child := range t {
			if p := findLeaf(child); p != nil {
				return p
			}
		}
	}
	return nil
}

func appendStrings(dst []string, v any) []string {
	switch t := v.(type) {
	case string:
		return append(dst, t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				dst = append(dst, s)
			}
		}
	}
	return dst
}

package store

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

const searchFieldMax = 1024

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title`)

// SearchText is the part of a zgrab2 result that text search matches against.
// Matching the whole raw result means detoasting kilobytes per candidate row,
// which takes tens of seconds on a small boid.
func SearchText(raw json.RawMessage, certNames []string) string {
	var top struct {
		Result json.RawMessage `json:"result"`
	}
	var res struct {
		Banner   string `json:"banner"`
		Response *struct {
			StatusLine string          `json:"status_line"`
			Headers    json.RawMessage `json:"headers"`
			Body       string          `json:"body"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &top) != nil || (len(top.Result) > 0 && json.Unmarshal(top.Result, &res) != nil) {
		return cleanSearchText(head(string(raw), 2*searchFieldMax))
	}
	var parts []string
	if r := res.Response; r != nil {
		parts = append(parts, r.StatusLine, head(string(r.Headers), searchFieldMax))
		if m := titleRE.FindStringSubmatch(r.Body); m != nil {
			parts = append(parts, head(m[1], 200))
		}
		parts = append(parts, head(r.Body, searchFieldMax))
	}
	if res.Banner != "" {
		parts = append(parts, head(res.Banner, searchFieldMax))
	}
	if res.Response == nil && res.Banner == "" {
		parts = append(parts, head(string(top.Result), searchFieldMax))
	}
	parts = append(parts, certNames...)
	return cleanSearchText(strings.Join(parts, " "))
}

// head cuts s to at most n bytes without splitting a UTF-8 sequence.
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Postgres text rejects NUL and invalid UTF-8; banners carry both.
func cleanSearchText(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", ""))
}

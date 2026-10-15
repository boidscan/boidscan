package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/boidscan/boidscan/internal/grab"
)

// Clock times in banners, e.g. an SMTP greeting's date.
var bannerTime = regexp.MustCompile(`\d{1,2}:\d{2}(:\d{2})?`)

// ChangeKey names what a result says about a service: a later result with the
// same key is the same service seen again, any other key starts a new history
// row. Raw results differ on every scan (TLS randoms, Date headers), so only
// fields that stay put while the service does are used.
func ChangeKey(protocol, status string, raw json.RawMessage) string {
	var top struct {
		Result struct {
			Banner   string `json:"banner"`
			ServerID *struct {
				Raw string `json:"raw"`
			} `json:"server_id"`
			Response *struct {
				StatusLine string              `json:"status_line"`
				Headers    map[string][]string `json:"headers"`
				Body       string              `json:"body"`
			} `json:"response"`
		} `json:"result"`
	}
	json.Unmarshal(raw, &top)
	r := top.Result
	parts := []string{protocol, status, grab.Fingerprint(raw), bannerTime.ReplaceAllString(head(r.Banner, searchFieldMax), "")}
	if r.ServerID != nil {
		parts = append(parts, r.ServerID.Raw)
	}
	if resp := r.Response; resp != nil {
		parts = append(parts, resp.StatusLine, strings.Join(resp.Headers["server"], ","))
		if m := titleRE.FindStringSubmatch(resp.Body); m != nil {
			parts = append(parts, strings.TrimSpace(head(m[1], 200)))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

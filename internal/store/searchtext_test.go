package store

import (
	"strings"
	"testing"
)

func TestSearchText(t *testing.T) {
	body := `<html><head>` + strings.Repeat("<script>x</script>", 100) + `<title>cPanel Login</title></head>` + strings.Repeat("a", 2000) + `deep`
	http := `{"status":"success","result":{"response":{"status_line":"200 OK","headers":{"server":["Apache"]},"body":` + quote(body) + `}}}`
	for name, tc := range map[string]struct {
		raw   string
		names []string
		want  []string
		not   []string
	}{
		"http":        {http, []string{"shop.example.org"}, []string{"200 ok", "apache", "cpanel login", "<script>", "shop.example.org"}, []string{"deep"}},
		"nul banner":  {`{"result":{"banner":"\u0000ÿLogin:"}}`, nil, []string{"ÿlogin:"}, []string{"\x00"}},
		"other":       {`{"result":{"server_id":{"raw":"SSH-2.0-OpenSSH_9.6"}}}`, nil, []string{"openssh_9.6"}, nil},
		"invalid":     {`{"result":`, nil, []string{`{"result":`}, nil},
		"wrong shape": {`{"result":{"banner":42}}`, nil, []string{`"banner":42`}, nil},
	} {
		got := SearchText([]byte(tc.raw), tc.names)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in %q", name, w, got)
			}
		}
		for _, w := range tc.not {
			if strings.Contains(got, w) {
				t.Errorf("%s: unexpected %q in %q", name, w, got)
			}
		}
	}
}

func TestHeadKeepsRunes(t *testing.T) {
	if got := head("aé", 2); got != "a" {
		t.Fatalf("head cut inside a rune: %q", got)
	}
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

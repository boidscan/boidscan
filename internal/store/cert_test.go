package store

import (
	"slices"
	"strings"
	"testing"

	"github.com/boidscan/boidscan/pkg/client"
)

func TestCertInfo(t *testing.T) {
	raw := `{"status":"success","result":{"response":{"request":{"tls_log":{"handshake_log":{"server_certificates":{"certificate":{"parsed":{
		"fingerprint_sha256":"ABCDEF",
		"subject":{"common_name":["Example.org"]},
		"extensions":{"subject_alt_name":{"dns_names":["example.org","www.example.org"]}}}}}}}}}}}`
	sha, names := CertInfo([]byte(raw))
	if sha != "abcdef" {
		t.Errorf("sha = %q", sha)
	}
	if want := []string{"example.org", "www.example.org"}; !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestCertInfoNone(t *testing.T) {
	sha, names := CertInfo([]byte(`{"status":"success","result":{"banner":"220 hi"}}`))
	if sha != "" || names != nil {
		t.Fatalf("got %q %v", sha, names)
	}
}

func TestBuildSearch(t *testing.T) {
	sql, args, err := buildSearch(client.Query{CIDR: "192.0.2.0/24", Port: 443, Text: "50%_OFF", Cert: "Example.org", Limit: 5000})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ip <<= $1", "port = $2", "search_text LIKE $3", "cert_sha256 = $4 OR cert_names @> ARRAY[$4]", "LIMIT $5"} {
		if !strings.Contains(sql, want) {
			t.Errorf("sql missing %q: %s", want, sql)
		}
	}
	if args[2] != `%50\%\_off%` {
		t.Errorf("LIKE pattern not escaped: %v", args[2])
	}
	if args[3] != "example.org" {
		t.Errorf("cert not lower-cased: %v", args[3])
	}
	if args[4] != maxLimit+1 {
		t.Errorf("limit not clamped: %v", args[4])
	}
}

func TestBuildSearchRejects(t *testing.T) {
	for _, q := range []client.Query{{CIDR: "nope"}, {Port: 70000}} {
		if _, _, err := buildSearch(q); err == nil {
			t.Errorf("query %+v must be rejected", q)
		}
	}
}

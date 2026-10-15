package store

import "testing"

func TestChangeKey(t *testing.T) {
	page := func(date, title string) string {
		return `{"status":"success","timestamp":"` + date + `","result":{"response":{"status_line":"200 OK","headers":{"server":["nginx"],"date":["` + date + `"]},"body":"<title>` + title + `</title>"}}}`
	}
	smtp := func(at string) string {
		return `{"result":{"banner":"220 mx.example.org ESMTP ` + at + `"}}`
	}
	same := ChangeKey("http", "success", []byte(page("Mon, 12 Oct 2026 08:00:00 GMT", "Shop")))
	for name, tc := range map[string]struct {
		a, b string
		want bool
	}{
		"http date only":  {page("Mon, 12 Oct 2026 08:00:00 GMT", "Shop"), page("Thu, 15 Oct 2026 09:30:12 GMT", "Shop"), true},
		"http title":      {page("Mon, 12 Oct 2026 08:00:00 GMT", "Shop"), page("Mon, 12 Oct 2026 08:00:00 GMT", "Login"), false},
		"smtp clock":      {smtp("Thu, 15 Oct 2026 08:07:47 +0000"), smtp("Thu, 15 Oct 2026 08:09:01 +0000"), true},
		"ssh version":     {`{"result":{"server_id":{"raw":"SSH-2.0-OpenSSH_9.6"}}}`, `{"result":{"server_id":{"raw":"SSH-2.0-OpenSSH_9.7"}}}`, false},
		"unparsable same": {`{"result":`, `{"result":`, true},
	} {
		if got := ChangeKey("p", "success", []byte(tc.a)) == ChangeKey("p", "success", []byte(tc.b)); got != tc.want {
			t.Errorf("%s: same key %v, want %v", name, got, tc.want)
		}
	}
	if same == ChangeKey("http", "io-timeout", []byte(page("Mon, 12 Oct 2026 08:00:00 GMT", "Shop"))) {
		t.Error("a different status kept the key")
	}
}

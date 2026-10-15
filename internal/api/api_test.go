package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
	"github.com/boidscan/boidscan/pkg/client"
)

type fakeBackend struct {
	hosts   map[netip.Addr]client.Host
	pages   []client.Page
	queries []client.Query
}

func (f *fakeBackend) Host(_ context.Context, ip netip.Addr) (client.Host, error) {
	if h, ok := f.hosts[ip]; ok {
		return h, nil
	}
	return client.Host{IP: ip.String()}, nil
}

func (f *fakeBackend) Search(_ context.Context, q client.Query) (client.Page, error) {
	if q.Port > 65535 {
		return client.Page{}, store.ErrBadQuery
	}
	if q.Text == "slow" {
		return client.Page{}, store.ErrSearchTimeout
	}
	f.queries = append(f.queries, q)
	p := f.pages[0]
	f.pages = f.pages[1:]
	return p, nil
}

var testID = policy.Identity{ProjectURL: "https://boidscan.example", AbuseContact: "abuse@boidscan.example"}

func TestClientRoundTrip(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.5")
	fb := &fakeBackend{
		hosts: map[netip.Addr]client.Host{ip: {IP: ip.String(), Services: []client.Observation{{ID: 1, IP: ip.String(), Port: 22, Name: "ssh22", Data: []byte(`{}`)}}}},
		pages: []client.Page{
			{Results: []client.Observation{{ID: 9}, {ID: 8}}, Next: 8},
			{Results: []client.Observation{{ID: 7}}},
		},
	}
	srv := httptest.NewServer(New(fb, testID).Handler())
	defer srv.Close()
	c := client.New(srv.URL)
	ctx := context.Background()

	h, err := c.Host(ctx, ip.String())
	if err != nil || len(h.Services) != 1 || h.Services[0].Port != 22 {
		t.Fatalf("Host = %+v, %v", h, err)
	}

	_, err = c.Host(ctx, "192.0.2.6")
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %v", err)
	}

	var ids []int64
	err = c.SearchAll(ctx, client.Query{Port: 443, Text: "nginx", Limit: 2}, func(o client.Observation) bool {
		ids = append(ids, o.ID)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || fb.queries[1].Before != 8 || fb.queries[0].Text != "nginx" || fb.queries[0].Port != 443 {
		t.Fatalf("paging broken: ids=%v queries=%+v", ids, fb.queries)
	}

	_, err = c.Search(ctx, client.Query{Port: 70000})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %v", err)
	}
	_, err = c.Search(ctx, client.Query{Text: "slow"})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %v", err)
	}
}

func TestIndexNamesIdentity(t *testing.T) {
	srv := httptest.NewServer(New(&fakeBackend{}, testID).Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{testID.ProjectURL, testID.AbuseContact} {
		if !strings.Contains(string(body), want) {
			t.Errorf("index page missing %q", want)
		}
	}
}

func TestSearchForm(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.5")
	fb := &fakeBackend{
		hosts: map[netip.Addr]client.Host{ip: {IP: ip.String(), Services: []client.Observation{{ID: 1, IP: ip.String(), Port: 22, Name: "ssh22", Data: []byte(`{"banner":"SSH-2.0-OpenSSH"}`)}}}},
		pages: []client.Page{
			{Results: []client.Observation{{ID: 9, IP: "192.0.2.9", Port: 80, Name: "http80", Data: []byte(`{}`)}}, Next: 9},
			{Results: []client.Observation{}},
		},
	}
	srv := httptest.NewServer(New(fb, testID).Handler())
	defer srv.Close()

	get := func(query string) (int, string) {
		resp, err := http.Get(srv.URL + "/?" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	code, body := get("q=192.0.2.5")
	if code != http.StatusOK || !strings.Contains(body, "ssh22") || !strings.Contains(body, "SSH-2.0-OpenSSH") {
		t.Fatalf("host search: %d %s", code, body)
	}
	code, body = get("q=nginx&port=80")
	if code != http.StatusOK || !strings.Contains(body, "192.0.2.9") || !strings.Contains(body, "before=9") {
		t.Fatalf("text search: %d %s", code, body)
	}
	if q := fb.queries[0]; q.Text != "nginx" || q.Port != 80 || q.CIDR != "" {
		t.Fatalf("text search query = %+v", q)
	}
	code, body = get("q=192.0.2.0/24")
	if code != http.StatusOK || !strings.Contains(body, "No results") || fb.queries[1].CIDR != "192.0.2.0/24" {
		t.Fatalf("cidr search: %d %+v", code, fb.queries)
	}
	if code, _ := get("q=x&port=abc"); code != http.StatusBadRequest {
		t.Fatalf("bad port: status %d, want 400", code)
	}
	if code, body := get("q=slow"); code != http.StatusServiceUnavailable || !strings.Contains(body, "took too long") {
		t.Fatalf("slow search: status %d, want 503: %s", code, body)
	}
}

type fakeFlock struct{ host client.Host }

func (f fakeFlock) Self() fed.Record                                      { return fed.Record{Name: "boid-a"} }
func (f fakeFlock) Peers(context.Context) ([]fed.Peer, error)             { return nil, nil }
func (f fakeFlock) Host(context.Context, netip.Addr) (client.Host, error) { return f.host, nil }

func TestHostLookupsGoThroughTheFlock(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.5")
	local := client.Host{IP: ip.String(), Services: []client.Observation{{Port: 22, Name: "ssh22"}}}
	merged := client.Host{IP: ip.String(), Services: []client.Observation{{Port: 22, Name: "ssh22"}, {Port: 80, Name: "http80"}}}
	s := New(&fakeBackend{hosts: map[netip.Addr]client.Host{ip: local}}, testID)
	s.SetFlock(fakeFlock{host: merged})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	c := client.New(srv.URL)

	if h, err := c.Host(context.Background(), ip.String()); err != nil || len(h.Services) != 2 {
		t.Fatalf("Host = %+v, %v; want the flock's merged result", h, err)
	}
	resp, err := http.Get(srv.URL + "/api/v1/host/" + ip.String() + "?local=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "http80") {
		t.Fatalf("local=1 must answer from this node only: %s", body)
	}
}

type fakeOptOuts struct {
	ip     netip.Addr
	action string
	err    error
}

func (f *fakeOptOuts) Request(_ context.Context, ip netip.Addr, action string) (fed.OptOut, error) {
	f.ip, f.action = ip, action
	return fed.OptOut{IP: ip, Action: action, Expires: time.Date(2027, 10, 15, 0, 0, 0, 0, time.UTC)}, f.err
}

func (f *fakeOptOuts) Status(_ context.Context, ip netip.Addr) (fed.OptOut, bool, error) {
	f.ip = ip
	return fed.OptOut{}, false, f.err
}

func TestOptOut(t *testing.T) {
	f := &fakeOptOuts{}
	s := New(&fakeBackend{}, testID)
	s.SetOptOuts(f)
	h := s.Handler()
	send := func(method, remote string, header http.Header) (int, string) {
		r := httptest.NewRequest(method, "/api/v1/optout", nil)
		r.RemoteAddr = remote
		for k, v := range header {
			r.Header[k] = v
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}

	code, body := send(http.MethodPost, "[::ffff:198.51.100.7]:5555", http.Header{"X-Forwarded-For": {"192.0.2.1"}})
	if code != http.StatusOK || f.ip != netip.MustParseAddr("198.51.100.7") || f.action != fed.OptOutAdd || !strings.Contains(body, `"opted_out":true`) {
		t.Fatalf("POST: %d %s, covered %s %s", code, body, f.ip, f.action)
	}
	if code, _ := send(http.MethodDelete, "198.51.100.8:4444", nil); code != http.StatusOK || f.action != fed.OptOutRemove || f.ip != netip.MustParseAddr("198.51.100.8") {
		t.Fatalf("DELETE: %d, %s %s", code, f.ip, f.action)
	}
	if code, body := send(http.MethodGet, "198.51.100.9:4444", nil); code != http.StatusOK || !strings.Contains(body, `"opted_out":false`) {
		t.Fatalf("GET: %d %s", code, body)
	}
	if code, _ := send(http.MethodPost, "198.51.100.7:1", http.Header{"Origin": {"https://evil.example"}}); code != http.StatusForbidden {
		t.Fatalf("POST from a web page: %d, want 403", code)
	}
	for err, want := range map[error]int{
		fed.ErrOptOutAddress: http.StatusBadRequest,
		fed.ErrOptOutRate:    http.StatusTooManyRequests,
		fed.ErrOptOutFull:    http.StatusServiceUnavailable,
		fed.ErrNotOptedOut:   http.StatusNotFound,
	} {
		f.err = err
		if code, _ := send(http.MethodPost, "198.51.100.7:1", nil); code != want {
			t.Errorf("%v: status %d, want %d", err, code, want)
		}
	}
}

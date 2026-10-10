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
}

package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	optouts []netip.Prefix
	purged  []netip.Prefix
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

func (f *fakeBackend) OptOuts(context.Context) ([]client.OptOut, error) {
	var out []client.OptOut
	for _, p := range f.optouts {
		out = append(out, client.OptOut{CIDR: p.String()})
	}
	return out, nil
}

func (f *fakeBackend) AddOptOut(_ context.Context, p netip.Prefix, _ string) error {
	f.optouts = append(f.optouts, p)
	return nil
}

func (f *fakeBackend) PurgeOptedOut(_ context.Context, p netip.Prefix) (int64, error) {
	f.purged = append(f.purged, p)
	return 0, nil
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
	for _, want := range []string{testID.ProjectURL, testID.AbuseContact, `action="/optout"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("index page missing %q", want)
		}
	}
}

func TestOptOutForm(t *testing.T) {
	fb := &fakeBackend{}
	srv := httptest.NewServer(New(fb, testID).Handler())
	defer srv.Close()

	post := func(cidr string) int {
		resp, err := http.PostForm(srv.URL+"/optout", url.Values{"cidr": {cidr}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("1.0.0.0/8"); got != http.StatusBadRequest {
		t.Errorf("/8 via form: status %d, want 400", got)
	}
	if got := post("garbage"); got != http.StatusBadRequest {
		t.Errorf("garbage: status %d, want 400", got)
	}
	if got := post("198.51.100.0/24"); got != http.StatusOK {
		t.Errorf("valid opt-out: status %d, want 200", got)
	}
	if len(fb.optouts) != 1 || len(fb.purged) != 1 || fb.purged[0].String() != "198.51.100.0/24" {
		t.Fatalf("opt-out not stored and purged: %+v %+v", fb.optouts, fb.purged)
	}
	if got := post("203.0.113.0/24"); got != http.StatusTooManyRequests {
		t.Errorf("second opt-out within a minute: status %d, want 429", got)
	}
}

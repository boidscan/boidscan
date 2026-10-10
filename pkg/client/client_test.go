package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSearchEncodesQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "before=5&cert=example.org&cidr=192.0.2.0%2F24&limit=10&port=443&q=nginx+1.29"
		if r.URL.Path != "/api/v1/search" || r.URL.RawQuery != want {
			t.Errorf("got %s?%s, want query %s", r.URL.Path, r.URL.RawQuery, want)
		}
		w.Write([]byte(`{"results":[{"id":4,"ip":"192.0.2.1","port":443}],"next":0}`))
	}))
	defer srv.Close()
	p, err := New(srv.URL+"/").Search(context.Background(), Query{CIDR: "192.0.2.0/24", Port: 443, Text: "nginx 1.29", Cert: "example.org", Before: 5, Limit: 10})
	if err != nil || len(p.Results) != 1 || p.Results[0].Port != 443 {
		t.Fatalf("Search = %+v, %v", p, err)
	}
}

func TestAPIErrorFromPlainText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := New(srv.URL).Host(context.Background(), "192.0.2.1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway || apiErr.Message != "upstream down" {
		t.Fatalf("got %v", err)
	}
}

func TestSearchAllStopsEarly(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"results":[{"id":3},{"id":2}],"next":2}`))
	}))
	defer srv.Close()
	n := 0
	err := New(srv.URL).SearchAll(context.Background(), Query{}, func(Observation) bool {
		n++
		return n < 3
	})
	if err != nil || n != 3 || calls != 2 {
		t.Fatalf("n=%d calls=%d err=%v", n, calls, err)
	}
}

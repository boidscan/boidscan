// Package api serves the public search API and the node info page.
package api

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
	"github.com/boidscan/boidscan/pkg/client"
)

//go:embed templates/index.html
var templates embed.FS

var indexTmpl = template.Must(template.New("index.html").Funcs(template.FuncMap{"pretty": prettyJSON}).ParseFS(templates, "templates/index.html"))

type Backend interface {
	Host(ctx context.Context, ip netip.Addr) (client.Host, error)
	Search(ctx context.Context, q client.Query) (client.Page, error)
}

// Flock is this node's view of the federation, shown on the info page.
type Flock interface {
	Self() fed.Record
	Peers(ctx context.Context) ([]fed.Peer, error)
}

type Server struct {
	backend  Backend
	identity policy.Identity
	flock    Flock
}

func New(b Backend, id policy.Identity) *Server {
	return &Server{backend: b, identity: id}
}

func (s *Server) SetFlock(f Flock) { s.flock = f }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /api/v1/host/{ip}", s.host)
	mux.HandleFunc("GET /api/v1/search", s.search)
	return mux
}

type indexData struct {
	policy.Identity
	UserAgent string
	Search    *searchView
	Flock     *flockView
}

type flockView struct {
	Self  fed.Record
	Peers []fed.Peer
}

type searchView struct {
	Query   string
	Port    string
	Results []client.Observation
	NextURL string
	Error   string
}

func (s *Server) render(w http.ResponseWriter, status int, d indexData) {
	d.Identity = s.identity
	d.UserAgent = s.identity.UserAgent()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := indexTmpl.Execute(w, d); err != nil {
		slog.Error("rendering index", "err", err)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	if !v.Has("q") && !v.Has("port") {
		d := indexData{}
		if s.flock != nil {
			peers, err := s.flock.Peers(r.Context())
			if err != nil {
				slog.Error("loading peers", "err", err)
			}
			d.Flock = &flockView{Self: s.flock.Self(), Peers: peers}
		}
		s.render(w, http.StatusOK, d)
		return
	}
	sv, status := s.runSearch(r.Context(), v)
	s.render(w, status, indexData{Search: sv})
}

// runSearch backs the search form: an address shows the latest result per
// service, a CIDR lists that range, anything else is a text search.
func (s *Server) runSearch(ctx context.Context, v url.Values) (*searchView, int) {
	sv := &searchView{Query: strings.TrimSpace(v.Get("q")), Port: strings.TrimSpace(v.Get("port"))}
	var q client.Query
	if sv.Port != "" {
		n, err := strconv.Atoi(sv.Port)
		if err != nil {
			sv.Error = "The port must be a number."
			return sv, http.StatusBadRequest
		}
		q.Port = n
	}
	if b := v.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil {
			sv.Error = "Invalid page."
			return sv, http.StatusBadRequest
		}
		q.Before = n
	}
	if p, err := netset.ParsePrefix(sv.Query); err == nil {
		if p.IsSingleIP() && q.Port == 0 && q.Before == 0 {
			h, err := s.backend.Host(ctx, p.Addr())
			if err != nil {
				slog.Error("host lookup", "err", err)
				sv.Error = "The lookup failed."
				return sv, http.StatusInternalServerError
			}
			sv.Results = h.Services
			return sv, http.StatusOK
		}
		q.CIDR = p.String()
	} else {
		q.Text = sv.Query
	}
	page, err := s.backend.Search(ctx, q)
	if errors.Is(err, store.ErrBadQuery) {
		sv.Error = err.Error()
		return sv, http.StatusBadRequest
	}
	if err != nil {
		slog.Error("search", "err", err)
		sv.Error = "The search failed."
		return sv, http.StatusInternalServerError
	}
	sv.Results = page.Results
	if page.Next != 0 {
		next := url.Values{"q": {sv.Query}, "port": {sv.Port}, "before": {strconv.FormatInt(page.Next, 10)}}
		sv.NextURL = "/?" + next.Encode()
	}
	return sv, http.StatusOK
}

func prettyJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	h, err := s.backend.Host(r.Context(), ip.Unmap())
	if err != nil {
		slog.Error("host lookup", "err", err)
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if len(h.Services) == 0 {
		writeError(w, http.StatusNotFound, "no data for this host")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := client.Query{CIDR: v.Get("cidr"), Text: v.Get("q"), Cert: v.Get("cert")}
	for name, dst := range map[string]*int{"port": &q.Port, "limit": &q.Limit} {
		if s := v.Get(name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid "+name)
				return
			}
			*dst = n
		}
	}
	if b := v.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid before")
			return
		}
		q.Before = n
	}
	page, err := s.backend.Search(r.Context(), q)
	if errors.Is(err, store.ErrBadQuery) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		slog.Error("search", "err", err)
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("writing response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

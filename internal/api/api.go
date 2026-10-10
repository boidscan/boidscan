// Package api serves the public search API, the node info page and the opt-out form.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/internal/store"
	"github.com/boidscan/boidscan/pkg/client"
)

// MinOptOutBits is the largest range the public form accepts.
const MinOptOutBits = 16

//go:embed templates/index.html
var templates embed.FS

var indexTmpl = template.Must(template.ParseFS(templates, "templates/index.html"))

type Backend interface {
	Host(ctx context.Context, ip netip.Addr) (client.Host, error)
	Search(ctx context.Context, q client.Query) (client.Page, error)
	OptOuts(ctx context.Context) ([]client.OptOut, error)
	AddOptOut(ctx context.Context, p netip.Prefix, contact string) error
	PurgeOptedOut(ctx context.Context, p netip.Prefix) (int64, error)
}

type Server struct {
	backend  Backend
	identity policy.Identity
	limiter  *limiter
}

func New(b Backend, id policy.Identity) *Server {
	return &Server{backend: b, identity: id, limiter: newLimiter(time.Minute)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /optout", s.optout)
	mux.HandleFunc("GET /api/v1/host/{ip}", s.host)
	mux.HandleFunc("GET /api/v1/search", s.search)
	mux.HandleFunc("GET /api/v1/optouts", s.optouts)
	return mux
}

type indexData struct {
	policy.Identity
	UserAgent string
	MinBits   int
	Message   string
	Error     bool
}

func (s *Server) renderIndex(w http.ResponseWriter, status int, msg string, isErr bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	err := indexTmpl.Execute(w, indexData{
		Identity:  s.identity,
		UserAgent: s.identity.UserAgent(),
		MinBits:   MinOptOutBits,
		Message:   msg,
		Error:     isErr,
	})
	if err != nil {
		slog.Error("rendering index", "err", err)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.renderIndex(w, http.StatusOK, "", false)
}

func (s *Server) optout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		s.renderIndex(w, http.StatusBadRequest, "Could not read the form.", true)
		return
	}
	p, err := netset.ParsePrefix(r.PostForm.Get("cidr"))
	if err != nil || !p.Addr().Is4() {
		s.renderIndex(w, http.StatusBadRequest, "That is not a valid IPv4 address or CIDR.", true)
		return
	}
	if p.Bits() < MinOptOutBits {
		s.renderIndex(w, http.StatusBadRequest, "That range is too large for the form. Please contact "+s.identity.AbuseContact+".", true)
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		s.renderIndex(w, http.StatusTooManyRequests, "Too many requests, please try again in a minute.", true)
		return
	}
	contact := r.PostForm.Get("contact")
	if len(contact) > 256 {
		contact = contact[:256]
	}
	if err := s.backend.AddOptOut(r.Context(), p, contact); err != nil {
		slog.Error("adding opt-out", "err", err)
		s.renderIndex(w, http.StatusInternalServerError, "Saving failed, please contact "+s.identity.AbuseContact+".", true)
		return
	}
	n, err := s.backend.PurgeOptedOut(r.Context(), p)
	if err != nil {
		slog.Error("purging opted-out range", "prefix", p, "err", err)
	}
	slog.Info("opt-out added", "prefix", p, "purged", n)
	s.renderIndex(w, http.StatusOK, p.String()+" is opted out and its stored results were deleted.", false)
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

func (s *Server) optouts(w http.ResponseWriter, r *http.Request) {
	list, err := s.backend.OptOuts(r.Context())
	if err != nil {
		slog.Error("listing opt-outs", "err", err)
		writeError(w, http.StatusInternalServerError, "listing failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
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

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter allows one event per key per interval. It is per process, which is
// enough for a single node; federation will move it to the coordinator.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

func newLimiter(interval time.Duration) *limiter {
	return &limiter{interval: interval, last: map[string]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.interval {
		return false
	}
	if len(l.last) > 10000 {
		for k, t := range l.last {
			if now.Sub(t) >= l.interval {
				delete(l.last, k)
			}
		}
	}
	l.last[key] = now
	return true
}

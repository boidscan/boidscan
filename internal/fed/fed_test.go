package fed

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

type memStore struct {
	mu       sync.Mutex
	peers    map[string]*Peer
	policies []flockpolicy.Policy
	pause    *flockpolicy.Pause
	// data loses the rows of revoked boids.
	data *memData
}

func newMemStore() *memStore { return &memStore{peers: map[string]*Peer{}} }

func (m *memStore) PolicyState(context.Context) (flockpolicy.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := flockpolicy.State{Expires: map[uint64]time.Time{}}
	for _, p := range m.policies {
		st.Expires[p.Serial] = p.Expires
	}
	if len(m.policies) > 0 {
		p := m.policies[len(m.policies)-1]
		st.Latest = &p
		if m.pause != nil && m.pause.Serial == p.Serial {
			st.Pause = m.pause
		}
	}
	return st, nil
}

func (m *memStore) Policies(context.Context) ([]flockpolicy.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.policies), nil
}

func (m *memStore) AddPolicy(_ context.Context, p flockpolicy.Policy) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := len(m.policies); n > 0 && m.policies[n-1].Serial >= p.Serial {
		return false, nil
	}
	m.policies = append(m.policies, p)
	return true, nil
}

func (m *memStore) AddPause(_ context.Context, p flockpolicy.Pause) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pause != nil && m.pause.Serial == p.Serial {
		return false, nil
	}
	m.pause = &p
	return true, nil
}

func (m *memStore) SyncRevoked(_ context.Context, ids []string, self string) error {
	m.mu.Lock()
	for _, p := range m.peers {
		switch {
		case slices.Contains(ids, p.ID):
			p.State = StateRevoked
		case p.State == StateRevoked:
			p.State, p.Verified = StateNew, false
		}
	}
	m.mu.Unlock()
	if m.data == nil {
		return nil
	}
	gone := func(id string) bool { return id != self && slices.Contains(ids, id) }
	m.data.mu.Lock()
	defer m.data.mu.Unlock()
	m.data.obs = slices.DeleteFunc(m.data.obs, func(o client.Observation) bool { return gone(o.NodeID) && !m.data.confirmed(o) })
	m.data.cov = slices.DeleteFunc(m.data.cov, func(c Coverage) bool { return gone(c.NodeID) })
	return nil
}

// testRoot signs the policies of every test flock.
var testRootKey, _ = identity.Generate()
var testRoot = flockpolicy.Maintainers{Keys: []string{testRootKey.ID()}, Threshold: 1}

// testPolicy is a signed policy for the lab catalog; edit may change it before signing.
func testPolicy(t *testing.T, serial uint64, issued time.Time, edit func(*flockpolicy.Body)) flockpolicy.Document {
	t.Helper()
	b := flockpolicy.Body{
		Serial:       serial,
		Issued:       issued,
		Expires:      issued.Add(flockpolicy.DefaultLifetime),
		MaxRatePPS:   1000,
		MinRescan:    flockpolicy.Duration(time.Hour),
		BumpInterval: flockpolicy.Duration(time.Hour),
		Catalog:      labCatalog.Hash(),
		Maintainers:  testRoot,
	}
	if edit != nil {
		edit(&b)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	d := flockpolicy.Document{Policy: raw}
	d.Sign(testRootKey)
	return d
}

// install gives b a policy the way an operator would, without gossip.
func (b *testBoid) install(t *testing.T, d flockpolicy.Document) {
	t.Helper()
	_, changed, err := flockpolicy.Adopt(context.Background(), b.store, testRoot, b.cfg.Key.ID(), flockpolicy.Bundle{Chain: []flockpolicy.Document{d}}, b.now())
	if err != nil || !changed {
		t.Fatalf("installing a policy on %s: changed %v, %v", b.cfg.Name, changed, err)
	}
}

func (m *memStore) SavePeer(_ context.Context, r Record) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[r.ID]
	if !ok {
		m.peers[r.ID] = &Peer{Record: r, State: StateNew}
		return true, true, nil
	}
	if !r.Time.After(p.Time) {
		return false, false, nil
	}
	if p.Endpoint != r.Endpoint {
		p.Verified, p.State = false, StateNew
	}
	p.Record = r
	return true, false, nil
}

func (m *memStore) Peers(context.Context) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Peer
	for _, p := range m.peers {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memStore) MarkVerified(_ context.Context, id, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok && p.Endpoint == endpoint {
		p.Verified = true
	}
	return nil
}

func (m *memStore) SetPeerState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok {
		p.State = state
	}
	return nil
}

func (m *memStore) DeletePeer(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
	return nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testBoid struct {
	*Node
	store   *memStore
	data    *memData
	srv     *httptest.Server
	offline atomic.Bool
}

// newBoid starts a boid on a loopback test server. The clock is shared so
// liveness can be tested without waiting.
func newBoid(t *testing.T, name string, clk *clock, seeds ...string) *testBoid {
	t.Helper()
	b := &testBoid{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.offline.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		if b.data != nil && strings.HasPrefix(r.URL.Path, "/api/v1/host/") {
			b.data.serveHost(w, r)
			return
		}
		b.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	key, _ := identity.Generate()
	st := newMemStore()
	b.Node = &Node{
		cfg:           Config{Key: key, Name: name, Endpoint: srv.URL, Contact: "abuse@example.org", Version: "v1.0.0", Seeds: seeds, Interval: time.Second, Root: testRoot},
		rootID:        testRoot.ID(),
		fetched:       map[string]string{},
		store:         st,
		client:        srv.Client(),
		resolver:      fakeResolver{},
		checkEndpoint: func(string) error { return nil },
		now:           clk.now,
	}
	b.store, b.srv = st, srv
	return b
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return f[host], nil
}

func peerStates(b *testBoid) map[string]string {
	peers, _ := b.store.Peers(context.Background())
	out := map[string]string{}
	for _, p := range peers {
		s := p.State
		if !p.Verified {
			s = "unverified"
		}
		out[p.Name] = s
	}
	return out
}

func rounds(boids []*testBoid, n int) {
	for range n {
		for _, b := range boids {
			b.Tick(context.Background())
		}
	}
}

func TestFlockForms(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	a := newBoid(t, "boid-a", clk)
	b := newBoid(t, "boid-b", clk, a.srv.URL)
	c := newBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}

	rounds(boids, 2)
	want := func(names ...string) map[string]string {
		m := map[string]string{}
		for _, n := range names {
			m[n] = StateAlive
		}
		return m
	}
	for _, x := range boids {
		var others []string
		for _, y := range boids {
			if y != x {
				others = append(others, y.cfg.Name)
			}
		}
		if got := peerStates(x); !maps.Equal(got, want(others...)) {
			t.Errorf("%s sees %v, want %v alive", x.cfg.Name, got, others)
		}
	}

	// boid-c stops; the others keep gossiping and notice.
	c.offline.Store(true)
	for range suspectAfter {
		clk.advance(time.Second)
		rounds(boids[:2], 1)
	}
	if s := peerStates(a)["boid-c"]; s != StateSuspect {
		t.Fatalf("after %d quiet intervals boid-c is %q on boid-a, want suspect", suspectAfter, s)
	}
	clk.advance((downAfter - suspectAfter) * time.Second)
	rounds(boids[:2], 1)
	if s := peerStates(b)["boid-c"]; s != StateDown {
		t.Fatalf("boid-c is %q on boid-b, want down", s)
	}

	// boid-c comes back and gossips with the peers it remembers.
	c.offline.Store(false)
	rounds([]*testBoid{c}, 1)
	rounds(boids[:2], 1)
	for _, x := range boids[:2] {
		if s := peerStates(x)["boid-c"]; s != StateAlive {
			t.Errorf("boid-c is %q on %s after returning, want alive", s, x.cfg.Name)
		}
	}
}

func TestScanners(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newBoid(t, "boid-a", clk)
	a.cfg.Endpoint = "http://192.0.2.2"
	key, _ := identity.Generate()
	for name, endpoint := range map[string]string{"boid-b": "http://192.0.2.10", "boid-c": "http://192.0.2.3"} {
		r := Record{Name: name, Endpoint: endpoint, Time: clk.now()}
		r.sign(key)
		key, _ = identity.Generate()
		a.store.SavePeer(context.Background(), r)
		if name == "boid-b" {
			a.store.MarkVerified(context.Background(), r.ID, endpoint)
		}
	}
	res, err := http.Get(a.srv.URL + "/fed/v1/scanners")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if got := string(body); got != "192.0.2.2\n192.0.2.10\n" {
		t.Fatalf("scanners = %q, want this boid and the verified peer only", got)
	}
}

func TestImpostorIsDropped(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newBoid(t, "boid-a", clk)
	b := newBoid(t, "boid-b", clk)

	// A record with its own key that points at boid-b's server.
	evilKey, _ := identity.Generate()
	evil := Record{Name: "evil", Endpoint: b.srv.URL, Time: clk.now()}
	evil.sign(evilKey)
	a.ingest(context.Background(), []Record{evil}, "test")
	if s := peerStates(a)["evil"]; s != "unverified" {
		t.Fatalf("evil record not stored for verification: %q", s)
	}
	a.Tick(context.Background())
	if _, ok := peerStates(a)["evil"]; ok {
		t.Fatal("record pointing at another boid's endpoint survived the challenge")
	}
}

func TestIngestRejectsBadRecords(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newBoid(t, "boid-a", clk)
	key, _ := identity.Generate()

	tampered := Record{Name: "boid-x", Endpoint: "http://192.0.2.7", Time: clk.now()}
	tampered.sign(key)
	tampered.Endpoint = "http://192.0.2.8"

	future := Record{Name: "boid-y", Endpoint: "http://192.0.2.9", Time: clk.now().Add(time.Hour)}
	future.sign(key)

	newline := Record{Name: "boid\nz", Endpoint: "http://192.0.2.10", Time: clk.now()}
	newline.sign(key)

	a.ingest(context.Background(), []Record{tampered, future, newline}, "test")
	if got := peerStates(a); len(got) != 0 {
		t.Fatalf("bad records stored: %v", got)
	}
}

func TestResolveSeeds(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newBoid(t, "boid-a", clk, "seeds.boidscan.test", "http://198.51.100.1/")
	a.cfg.Endpoint = "http://192.0.2.2"
	a.resolver = fakeResolver{"seeds.boidscan.test": {"192.0.2.3", "192.0.2.2", "2001:db8::1", "192.0.2.1"}}
	got := a.resolveSeeds(context.Background(), true)
	want := []string{"http://192.0.2.1", "http://192.0.2.3", "http://198.51.100.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("seeds = %v, want %v (own endpoint and IPv6 removed)", got, want)
	}
}

func TestCheckEndpoint(t *testing.T) {
	for endpoint, wantOK := range map[string]bool{
		"http://8.8.8.8":           true,
		"http://8.8.8.8/":          false,
		"http://8.8.8.8:8080":      false,
		"https://8.8.8.8":          false,
		"http://example.org":       false,
		"http://10.0.0.1":          false,
		"http://127.0.0.1":         false,
		"http://8.8.8.8/x":         false,
		"http://user@8.8.8.8":      false,
		"http://[2001:4860::8888]": false,
	} {
		if err := checkEndpoint(endpoint, false); (err == nil) != wantOK {
			t.Errorf("checkEndpoint(%q) = %v", endpoint, err)
		}
	}
	if err := checkEndpoint("http://10.0.0.1", true); err != nil {
		t.Errorf("lab mode must allow private endpoints: %v", err)
	}
}

package fed

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/pkg/sig"
)

const (
	StateNew     = "new"
	StateAlive   = "alive"
	StateSuspect = "suspect"
	StateDown    = "down"
	// StateRevoked peers are named in the flock policy; nobody works with them.
	StateRevoked = "revoked"

	// A peer is suspect after this many gossip intervals without a fresher
	// record, and down after downAfter.
	suspectAfter = 5
	downAfter    = 30

	fanout        = 3
	maxRecords    = 256
	maxClockSkew  = 2 * time.Minute
	verifyPerTick = 8
	seedEvery     = 10
	// policyURLEvery is how often the project's policy URL is checked.
	policyURLEvery = time.Hour
)

type Peer struct {
	Record
	FirstSeen time.Time `json:"first_seen"`
	Verified  bool      `json:"verified"`
	State     string    `json:"state"`
	// Trust and LowReach are this boid's own judgement of the peer.
	Trust    string `json:"trust"`
	LowReach bool   `json:"low_reach"`
}

type Store interface {
	// SavePeer stores r unless a record with the same or a newer time is
	// already known. A changed endpoint clears the verification.
	SavePeer(ctx context.Context, r Record) (saved, isNew bool, err error)
	Peers(ctx context.Context) ([]Peer, error)
	// MarkVerified succeeds only if the peer still has this endpoint.
	MarkVerified(ctx context.Context, id, endpoint string) error
	SetPeerState(ctx context.Context, id, state string) error
	DeletePeer(ctx context.Context, id string) error

	flockpolicy.Store
	// Policies lists the stored policies, oldest first.
	Policies(ctx context.Context) ([]flockpolicy.Policy, error)
}

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Config struct {
	Key        Signer
	Name       string
	Endpoint   string
	Contact    string
	ProjectURL string
	Version    string
	// Seeds are http(s) URLs of boids, or DNS names whose A records are boids.
	Seeds    []string
	Interval time.Duration
	// AllowPrivate accepts RFC 1918 endpoints and results, for the lab.
	AllowPrivate bool
	// Root is the maintainer set the first flock policy must be signed by.
	Root flockpolicy.Maintainers
	// PolicyURL is checked hourly for a newer policy bundle; empty disables it.
	PolicyURL string

	Catalog catalog.Catalog
	// Data enables replication, routed host lookups and leases. Without it
	// the boid only takes part in discovery.
	Data     Data
	LeaseTTL time.Duration

	Trust TrustConfig
	// Check grabs targets for samples and returns a result for each, in
	// order. Without it this boid answers no check requests.
	Check func(ctx context.Context, targets []CheckTarget) ([]CheckResult, error)
	// Forge makes this boid defend its own false reports when asked to check
	// them, for the lab.
	Forge bool
}

type Node struct {
	cfg           Config
	catalogHash   string
	rootID        string
	store         Store
	client        *http.Client
	resolver      Resolver
	checkEndpoint func(string) error
	now           func() time.Time

	mu        sync.Mutex
	ticks     int
	lastSeeds string
	// policy is refreshed from the store every tick, for the own record and seeds.
	policy flockpolicy.State
	halt   string
	// fetched remembers which serial was last fetched from each peer, so a
	// peer that advertises a policy it cannot show is asked only once.
	fetched    map[string]string
	urlFetched time.Time
	// progressLog is the last progress line logged, to log only changes.
	progressLog string
}

func New(cfg Config, st Store) (*Node, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 10 * time.Minute
	}
	if cfg.Trust.TrustAfter == 0 {
		cfg.Trust = DefaultTrust()
	}
	n := &Node{
		cfg:         cfg,
		catalogHash: cfg.Catalog.Hash(),
		rootID:      cfg.Root.ID(),
		store:       st,
		// Shorter than the interval, or a dead peer delays the next round.
		client:   &http.Client{Timeout: min(max(cfg.Interval, time.Second), 5*time.Second)},
		resolver: net.DefaultResolver,
		checkEndpoint: func(e string) error {
			return checkEndpoint(e, cfg.AllowPrivate)
		},
		now:     time.Now,
		fetched: map[string]string{},
	}
	if err := n.checkEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	if err := n.Self().verify(); err != nil {
		return nil, fmt.Errorf("own node record: %w", err)
	}
	return n, nil
}

// Self is this boid's record, freshly signed.
func (n *Node) Self() Record {
	st := n.policyState()
	r := Record{
		Name:           n.cfg.Name,
		Endpoint:       n.cfg.Endpoint,
		Contact:        n.cfg.Contact,
		ProjectURL:     n.cfg.ProjectURL,
		Version:        n.cfg.Version,
		Catalog:        n.catalogHash,
		Root:           n.rootID,
		PolicySerial:   st.Serial(),
		EmergencyPause: st.Paused(n.now()),
		Time:           n.now(),
	}
	r.sign(n.cfg.Key)
	return r
}

func (n *Node) Peers(ctx context.Context) ([]Peer, error) { return n.store.Peers(ctx) }

func (n *Node) Run(ctx context.Context) {
	self := n.Self()
	slog.Info("I am "+self.Label()+", reachable at "+self.Endpoint, "id", self.ID, "gossip_every", n.cfg.Interval.String(),
		"catalog", n.cfg.Catalog.Name+" "+sig.Short(n.catalogHash), "root", sig.Short(n.rootID))
	if n.cfg.Data != nil {
		go n.replicateLoop(ctx)
		go n.trustLoop(ctx)
		go n.progressLoop(ctx)
	}
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		n.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick runs one gossip round, then verifies newcomers and updates liveness.
func (n *Node) Tick(ctx context.Context) {
	n.mu.Lock()
	n.ticks++
	tick := n.ticks
	n.mu.Unlock()
	n.loadPolicy(ctx)

	peers, err := n.store.Peers(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	var targets []string
	for _, p := range gossipable(peers) {
		targets = append(targets, p.Endpoint)
	}
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	targets = targets[:min(fanout, len(targets))]
	if len(targets) == 0 || tick%seedEvery == 1 {
		seeds := n.resolveSeeds(ctx, len(targets) == 0)
		if len(targets) > 0 && len(seeds) > 0 {
			seeds = seeds[rand.IntN(len(seeds)):][:1]
		}
		for _, s := range seeds {
			if !slices.Contains(targets, s) {
				targets = append(targets, s)
			}
		}
	}
	// In parallel, so one unreachable peer cannot delay news from the others.
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Go(func() { n.exchange(ctx, t, peers) })
	}
	wg.Wait()

	if peers, err = n.store.Peers(ctx); err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	verifying := 0
	n.syncPolicy(ctx, peers)
	for _, p := range peers {
		if !p.Verified && p.State != StateRevoked && verifying < verifyPerTick {
			verifying++
			wg.Go(func() { n.verify(ctx, p) })
		}
	}
	wg.Wait()
	if n.updateStates(ctx) || tick == 1 {
		n.logFlock(ctx)
	}
}

// gossipable are the verified peers that are not known to be down.
func gossipable(peers []Peer) []Peer {
	var out []Peer
	for _, p := range peers {
		if p.Verified && p.State != StateDown && p.State != StateRevoked {
			out = append(out, p)
		}
	}
	return out
}

func (n *Node) resolveSeeds(ctx context.Context, bootstrapping bool) []string {
	var urls, notes []string
	seeds := slices.Clone(n.cfg.Seeds)
	if p := n.policyState().Latest; p != nil {
		for _, s := range p.Seeds {
			if !slices.Contains(seeds, s) {
				seeds = append(seeds, s)
			}
		}
	}
	for _, s := range seeds {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			urls = append(urls, strings.TrimSuffix(s, "/"))
			notes = append(notes, s)
			continue
		}
		addrs, err := n.resolver.LookupHost(ctx, s)
		if err != nil {
			slog.Warn("DNS seed "+s+" did not resolve", "err", err)
			continue
		}
		var found []string
		for _, a := range addrs {
			if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
				found = append(found, "http://"+a)
			}
		}
		slices.Sort(found)
		notes = append(notes, s+" -> "+strings.Join(found, ", "))
		urls = append(urls, found...)
	}
	urls = slices.DeleteFunc(urls, func(u string) bool { return u == n.cfg.Endpoint })

	n.mu.Lock()
	changed := n.lastSeeds != strings.Join(notes, "; ")
	n.lastSeeds = strings.Join(notes, "; ")
	n.mu.Unlock()
	switch {
	case bootstrapping && len(seeds) == 0:
		slog.Debug("no peers and no seeds; waiting for another boid to contact this one")
	case bootstrapping && changed && len(notes) > 0:
		slog.Info("looking for the flock through seeds: " + strings.Join(notes, "; "))
	case bootstrapping:
		slog.Debug("contacting seeds", "seeds", urls)
	}
	return urls
}

type gossipMsg struct {
	Records []Record `json:"records"`
}

// sample is what this boid tells others: itself plus the peers it vouches for.
func (n *Node) sample(peers []Peer) gossipMsg {
	m := gossipMsg{Records: []Record{n.Self()}}
	known := gossipable(peers)
	rand.Shuffle(len(known), func(i, j int) { known[i], known[j] = known[j], known[i] })
	for _, p := range known[:min(maxRecords-1, len(known))] {
		m.Records = append(m.Records, p.Record)
	}
	return m
}

func (n *Node) exchange(ctx context.Context, endpoint string, peers []Peer) {
	msg := n.sample(peers)
	body, err := json.Marshal(msg)
	if err != nil {
		slog.Error("encoding gossip", "err", err)
		return
	}
	var resp gossipMsg
	if err := n.call(ctx, http.MethodPost, endpoint+"/fed/v1/gossip", body, &resp); err != nil {
		slog.Debug("gossip failed", "endpoint", endpoint, "err", err)
		return
	}
	via := endpoint
	if len(resp.Records) > 0 && resp.Records[0].Endpoint == endpoint {
		via = resp.Records[0].Label()
	}
	slog.Debug("gossiped", "with", via, "sent", len(msg.Records), "received", len(resp.Records))
	n.ingest(ctx, resp.Records, via)
}

func (n *Node) call(ctx context.Context, method, url string, body []byte, out any) error {
	return call(ctx, n.client, method, url, body, out)
}

func call(ctx context.Context, c *http.Client, method, url string, body []byte, out any) error {
	return callWith(ctx, c, method, url, body, nil, out)
}

func (n *Node) ingest(ctx context.Context, records []Record, via string) {
	if len(records) > maxRecords {
		records = records[:maxRecords]
	}
	self := n.cfg.Key.ID()
	pol := n.policyState().Latest
	for _, r := range records {
		if r.ID == self || pol.Revoked(r.ID) {
			continue
		}
		if err := r.verify(); err != nil {
			slog.Warn("ignored a node record from "+via, "id", r.ID, "err", err)
			continue
		}
		if r.Time.After(n.now().Add(maxClockSkew)) {
			slog.Warn("ignored a node record from the future from "+via, "peer", r.Label(), "time", r.Time)
			continue
		}
		saved, isNew, err := n.store.SavePeer(ctx, r)
		if err != nil {
			slog.Error("saving peer", "err", err)
			continue
		}
		switch {
		case isNew && via == r.Label():
			slog.Info(r.Label()+" introduced itself", "endpoint", r.Endpoint)
		case isNew:
			slog.Info("heard about "+r.Label()+" from "+via, "endpoint", r.Endpoint)
		case saved:
			slog.Debug("fresher record", "peer", r.Label(), "via", via, "time", r.Time)
		}
	}
}

type challengeResponse struct {
	Record         Record `json:"record"`
	NonceSignature []byte `json:"nonce_signature,omitempty"`
}

func challengeMessage(nonce, endpoint string) []byte {
	return sig.Message("boidscan-challenge-v1", nonce, endpoint)
}

// verify asks the boid at p's endpoint to sign a random nonce. Only the owner
// of p's key can, so a record cannot point at someone else's server.
func (n *Node) verify(ctx context.Context, p Peer) {
	if err := n.checkEndpoint(p.Endpoint); err != nil {
		slog.Warn("dropped "+p.Label(), "err", err)
		n.drop(ctx, p.ID)
		return
	}
	nonce := crand.Text()
	var resp challengeResponse
	if err := n.call(ctx, http.MethodGet, p.Endpoint+"/fed/v1/node?nonce="+nonce, nil, &resp); err != nil {
		slog.Debug("challenge unanswered, will retry", "peer", p.Label(), "endpoint", p.Endpoint, "err", err)
		return
	}
	if resp.Record.ID != p.ID || !sig.Verify(p.ID, challengeMessage(nonce, p.Endpoint), resp.NonceSignature) {
		slog.Warn("dropped "+p.Label()+": the boid at "+p.Endpoint+" does not hold its key", "answered_as", sig.Short(resp.Record.ID))
		n.drop(ctx, p.ID)
		return
	}
	if err := n.store.MarkVerified(ctx, p.ID, p.Endpoint); err != nil {
		slog.Error("marking peer verified", "err", err)
		return
	}
	slog.Info("verified " + p.Label() + ": the boid at " + p.Endpoint + " signed a challenge with its key")
	n.ingest(ctx, []Record{resp.Record}, p.Label())
}

func (n *Node) drop(ctx context.Context, id string) {
	if err := n.store.DeletePeer(ctx, id); err != nil {
		slog.Error("dropping peer", "err", err)
	}
}

func (n *Node) stateFor(age time.Duration) string {
	switch {
	case age >= downAfter*n.cfg.Interval:
		return StateDown
	case age >= suspectAfter*n.cfg.Interval:
		return StateSuspect
	}
	return StateAlive
}

// updateStates reports whether any verified peer changed state.
func (n *Node) updateStates(ctx context.Context) bool {
	peers, err := n.store.Peers(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return false
	}
	now := n.now()
	changed := false
	for _, p := range peers {
		if p.State == StateRevoked {
			continue
		}
		age := now.Sub(p.Time)
		want := n.stateFor(age)
		if !p.Verified {
			if want == StateDown {
				slog.Debug("forgot an unverified peer that never answered", "peer", p.Label())
				n.drop(ctx, p.ID)
			}
			continue
		}
		if want == p.State {
			continue
		}
		if err := n.store.SetPeerState(ctx, p.ID, want); err != nil {
			slog.Error("updating peer state", "err", err)
			continue
		}
		changed = true
		quiet := age.Truncate(time.Second).String()
		switch {
		case want == StateSuspect:
			slog.Info(p.Label() + " has been quiet for " + quiet + ", marking it suspect")
		case want == StateDown:
			slog.Info(p.Label() + " is down: no news for " + quiet)
		case p.State != StateNew:
			slog.Info(p.Label() + " is back")
		}
	}
	return changed
}

func (n *Node) logFlock(ctx context.Context) {
	peers, err := n.store.Peers(ctx)
	if err != nil {
		return
	}
	byState := map[string][]string{}
	for _, p := range peers {
		if p.Verified || p.State == StateRevoked {
			byState[p.State] = append(byState[p.State], p.Name)
		}
	}
	var parts []string
	for _, s := range []string{StateAlive, StateSuspect, StateDown, StateRevoked} {
		if names := byState[s]; len(names) > 0 {
			slices.Sort(names)
			parts = append(parts, fmt.Sprintf("%d %s (%s)", len(names), s, strings.Join(names, ", ")))
		}
	}
	if len(parts) == 0 {
		parts = []string{"no peers"}
	}
	slog.Info("flock: " + strings.Join(parts, ", "))
}

func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fed/v1/node", n.handleNode)
	mux.HandleFunc("POST /fed/v1/gossip", n.handleGossip)
	mux.HandleFunc("GET /fed/v1/peers", n.handlePeers)
	mux.HandleFunc("GET /fed/v1/scanners", n.handleScanners)
	mux.HandleFunc("GET /fed/v1/revoked", n.handleRevoked)
	mux.HandleFunc("GET /fed/v1/policy", n.handlePolicy)
	mux.HandleFunc("GET /fed/v1/policy/status", n.handlePolicyStatus)
	if n.cfg.Data != nil {
		mux.HandleFunc("POST /fed/v1/push", n.handlePush)
		mux.HandleFunc("POST /fed/v1/lease", n.handleLease)
		mux.HandleFunc("GET /fed/v1/due", n.handleDue)
		mux.HandleFunc("GET /fed/v1/units", n.handleUnits)
		mux.HandleFunc("GET /fed/v1/progress", n.handleProgress)
		mux.HandleFunc("GET /fed/v1/runs", n.handleRuns)
		mux.HandleFunc("GET /fed/v1/homes", n.handleHomes)
		mux.HandleFunc("POST /fed/v1/check", n.handleCheck)
		mux.HandleFunc("GET /fed/v1/check/{key}", n.handleCheckResult)
	}
	return mux
}

func (n *Node) handleNode(w http.ResponseWriter, r *http.Request) {
	resp := challengeResponse{Record: n.Self()}
	if nonce := r.URL.Query().Get("nonce"); nonce != "" {
		if len(nonce) > 64 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce too long"})
			return
		}
		resp.NonceSignature = n.cfg.Key.Sign(challengeMessage(nonce, n.cfg.Endpoint))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (n *Node) handleGossip(w http.ResponseWriter, r *http.Request) {
	var msg gossipMsg
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&msg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid gossip"})
		return
	}
	via := r.RemoteAddr
	if len(msg.Records) > 0 && msg.Records[0].verify() == nil {
		via = msg.Records[0].Label()
	}
	slog.Debug("gossip received", "from", via, "records", len(msg.Records))
	n.ingest(r.Context(), msg.Records, via)
	peers, err := n.store.Peers(r.Context())
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, n.sample(peers))
}

type peersView struct {
	Self  Record `json:"self"`
	Peers []Peer `json:"peers"`
}

func (n *Node) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers, err := n.store.Peers(r.Context())
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if peers == nil {
		peers = []Peer{}
	}
	writeJSON(w, http.StatusOK, peersView{Self: n.Self(), Peers: peers})
}

// handleScanners lists the address of this boid and of every verified peer,
// including down ones that may return, for firewall block lists.
func (n *Node) handleScanners(w http.ResponseWriter, r *http.Request) {
	peers, err := n.store.Peers(r.Context())
	if err != nil {
		slog.Error("loading peers", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	endpoints := []string{n.cfg.Endpoint}
	for _, p := range peers {
		if p.Verified && p.State != StateRevoked {
			endpoints = append(endpoints, p.Endpoint)
		}
	}
	writeIPs(w, endpoints)
}

// handleRevoked lists the last known address of every revoked boid, for
// firewall block lists: they may still scan, outside the flock.
func (n *Node) handleRevoked(w http.ResponseWriter, r *http.Request) {
	peers, err := n.store.Peers(r.Context())
	if err != nil {
		slog.Error("loading peers", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var endpoints []string
	for _, p := range peers {
		if p.State == StateRevoked {
			endpoints = append(endpoints, p.Endpoint)
		}
	}
	writeIPs(w, endpoints)
}

func writeIPs(w http.ResponseWriter, endpoints []string) {
	var ips []netip.Addr
	for _, e := range endpoints {
		if ip, err := netip.ParseAddr(strings.TrimPrefix(e, "http://")); err == nil {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, ip := range slices.Compact(ips) {
		fmt.Fprintln(w, ip)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("writing response", "err", err)
	}
}

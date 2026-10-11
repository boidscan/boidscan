package fed

import (
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

// Data is what a boid stores about blocks: results, coverage, leases and
// what it has already pushed to which home.
type Data interface {
	Host(ctx context.Context, ip netip.Addr) (client.Host, error)
	Excluded(ctx context.Context, ip netip.Addr) (bool, error)
	// ObservationsAfter and CoverageAfter return signed rows in id order.
	ObservationsAfter(ctx context.Context, after int64, limit int) ([]client.Observation, error)
	CoverageAfter(ctx context.Context, after int64, limit int) ([]Coverage, error)
	// AddRemoteObservations skips observations already stored and ones in excluded ranges.
	AddRemoteObservations(ctx context.Context, obs []client.Observation) (int, error)
	// AddCoverage also ends the scanner's lease on the unit.
	AddCoverage(ctx context.Context, cov []Coverage) (int, error)
	ReplicaState(ctx context.Context, home string) (ReplicaState, error)
	SaveReplicaState(ctx context.Context, home string, s ReplicaState) error
	// AcquireLease grants or renews a lease unless another holder has an
	// unexpired one or the unit was scanned within minRescan.
	AcquireLease(ctx context.Context, u catalog.Unit, holder string, ttl, minRescan time.Duration) (bool, error)
	ReleaseLease(ctx context.Context, u catalog.Unit, holder string) error
	// UnitStatus lists units with coverage or an unexpired lease.
	UnitStatus(ctx context.Context) ([]UnitStatus, error)
	SweepRuns(ctx context.Context, limit int) ([]Run, error)

	TrustData
}

// Coverage says that NodeID scanned a unit, so "nothing open" is data too.
type Coverage struct {
	ID        int64        `json:"id,omitempty"`
	Block     netip.Prefix `json:"block"`
	Group     int          `json:"group"`
	Catalog   string       `json:"catalog"`
	NodeID    string       `json:"node_id"`
	ScannedAt time.Time    `json:"scanned_at"`
	Signature []byte       `json:"signature"`
}

func (c Coverage) Unit() catalog.Unit { return catalog.Unit{Block: c.Block, Group: c.Group} }

func (c Coverage) message() []byte {
	return sig.Message("boidscan-coverage-v1", c.Block.String(), strconv.Itoa(c.Group), c.Catalog, c.NodeID, sig.Time(c.ScannedAt))
}

func SignCoverage(k Signer, u catalog.Unit, catalogHash string, at time.Time) Coverage {
	c := Coverage{Block: u.Block, Group: u.Group, Catalog: catalogHash, NodeID: k.ID(), ScannedAt: at.UTC().Truncate(time.Microsecond)}
	c.Signature = k.Sign(c.message())
	return c
}

func (c Coverage) Verify() bool { return sig.Verify(c.NodeID, c.message(), c.Signature) }

type UnitStatus struct {
	catalog.Unit
	ScannedAt time.Time `json:"scanned_at,omitzero"`
	ScannedBy string    `json:"scanned_by,omitempty"`
	LeasedBy  string    `json:"leased_by,omitempty"`
}

// Run is a sweep scan this boid ran.
type Run struct {
	ID int64 `json:"id"`
	catalog.Unit
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Error      string    `json:"error,omitempty"`
}

// ReplicaState is how far this boid has pushed its rows to one home. When the
// view changes, the push restarts from the first row but skips rows the home
// already got under the Old view, up to OldObs and OldCov.
type ReplicaState struct {
	View    []string
	Obs     int64
	Cov     int64
	CatchUp bool
	Old     []string
	OldObs  int64
	OldCov  int64
}

const (
	pushBatch      = 100
	batchesPerPush = 20
	maxPushBody    = 32 << 20
)

type pushMsg struct {
	Observations []client.Observation `json:"observations"`
	Coverage     []Coverage           `json:"coverage"`
}

// pushResult asks the sender to retry when this boid does not hold some of
// the blocks yet; views differ for a few gossip rounds after a change.
type pushResult struct {
	Stored   int  `json:"stored"`
	Rejected int  `json:"rejected"`
	Retry    bool `json:"retry"`
}

func (n *Node) selfMember() Member {
	return Member{ID: n.cfg.Key.ID(), Name: n.cfg.Name, Endpoint: n.cfg.Endpoint}
}

// flock is a view plus what it was built from.
type flock struct {
	View
	// all places blocks on every peer this boid cooperates with, as a boid
	// that trusts nobody yet does.
	all   View
	state flockpolicy.State
	peers map[string]Peer
	coop  func(Peer) bool
}

// holds reports whether this boid takes results and grants leases for block.
// Boids trust different peers, so their views differ: besides its own view,
// a boid accepts the view of a boid that trusts nobody yet.
func (f flock) holds(block netip.Prefix) bool {
	return f.IsHome(block, f.self) || f.all.IsHome(block, f.self)
}

// cooperating reports whether id is a peer this boid works with in any role.
func (f flock) cooperating(id string) bool {
	p, ok := f.peers[id]
	return ok && f.coop(p)
}

// mayLease reports whether id may scan for the flock: shunned peers and peers
// that miss too much may not.
func (f flock) mayLease(id string) bool {
	return id == f.self || (f.cooperating(id) && !f.peers[id].LowReach)
}

// rejects reports whether results signed by id are refused.
func (f flock) rejects(id string) bool {
	return f.state.Latest.Revoked(id) || f.peers[id].Trust == TrustShunned
}

func (n *Node) view(ctx context.Context) (flock, error) {
	st, err := n.store.PolicyState(ctx)
	if err != nil {
		return flock{}, err
	}
	peers, err := n.store.Peers(ctx)
	if err != nil {
		return flock{}, err
	}
	f := flock{state: st, peers: map[string]Peer{}, coop: n.cooperates(st, n.now())}
	for _, p := range peers {
		f.peers[p.ID] = p
	}
	f.View = NewView(n.selfMember(), peers, n.cfg.Catalog, homeEligible(peers, n.cfg.Catalog.Replicas, f.coop))
	f.all = NewView(n.selfMember(), peers, n.cfg.Catalog, f.coop)
	return f, nil
}

// replicateLoop pushes results to their homes, separately from gossip so a
// large backlog does not delay membership news.
func (n *Node) replicateLoop(ctx context.Context) {
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		n.Replicate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Replicate pushes every stored row to the current homes of its block. Homes
// that changed get the blocks they gained, from whichever boid holds them.
func (n *Node) Replicate(ctx context.Context) {
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	for _, m := range f.Others() {
		if err := n.pushTo(ctx, f.View, m); err != nil {
			slog.Error("replicating to "+m.Label(), "err", err)
		}
	}
}

func (n *Node) pushTo(ctx context.Context, v View, m Member) error {
	st, err := n.cfg.Data.ReplicaState(ctx, m.ID)
	if err != nil {
		return err
	}
	if ids := v.IDs(); !slices.Equal(st.View, ids) {
		if st.View != nil {
			if !st.CatchUp {
				st.CatchUp, st.Old, st.OldObs, st.OldCov = true, st.View, st.Obs, st.Cov
			}
			st.Obs, st.Cov = 0, 0
		}
		st.View = ids
	}
	want := func(block netip.Prefix, id, until int64) bool {
		if !v.IsHome(block, m.ID) {
			return false
		}
		return !st.CatchUp || id > until || !slices.Contains(homes(block, st.Old, n.cfg.Catalog.Replicas), m.ID)
	}
	var sentObs, sentCov int
	for range batchesPerPush {
		obs, err := n.cfg.Data.ObservationsAfter(ctx, st.Obs, pushBatch)
		if err != nil {
			return err
		}
		cov, err := n.cfg.Data.CoverageAfter(ctx, st.Cov, pushBatch)
		if err != nil {
			return err
		}
		if len(obs) == 0 && len(cov) == 0 {
			break
		}
		var msg pushMsg
		for _, o := range obs {
			if ip, err := netip.ParseAddr(o.IP); err == nil && want(n.cfg.Catalog.Block(ip), o.ID, st.OldObs) {
				msg.Observations = append(msg.Observations, o)
			}
		}
		for _, c := range cov {
			if want(c.Block, c.ID, st.OldCov) {
				msg.Coverage = append(msg.Coverage, c)
			}
		}
		if len(msg.Observations)+len(msg.Coverage) > 0 {
			body, err := json.Marshal(msg)
			if err != nil {
				return err
			}
			var res pushResult
			if err := n.signedCall(ctx, http.MethodPost, m.Endpoint+"/fed/v1/push", body, &res); err != nil {
				slog.Debug("push failed, will retry", "home", m.Label(), "err", err)
				break
			}
			if res.Retry {
				slog.Debug("home asked to retry the push later", "home", m.Label(), "stored", res.Stored)
				break
			}
			sentObs += len(msg.Observations)
			sentCov += len(msg.Coverage)
		}
		if len(obs) > 0 {
			st.Obs = obs[len(obs)-1].ID
		}
		if len(cov) > 0 {
			st.Cov = cov[len(cov)-1].ID
		}
		if st.CatchUp && st.Obs >= st.OldObs && st.Cov >= st.OldCov {
			st.CatchUp, st.Old = false, nil
		}
	}
	if sentObs+sentCov > 0 {
		slog.Info("pushed "+strconv.Itoa(sentObs)+" results and "+strconv.Itoa(sentCov)+" coverage records to "+m.Label(), "home", m.Endpoint)
	}
	return n.cfg.Data.SaveReplicaState(ctx, m.ID, st)
}

// handlePush stores results for blocks this boid holds, or that a peer it
// accepts as a home says it holds. Results of a peer it works with come from
// anyone it works with; results of departed or unknown scanners only through
// a peer it accepts as a home.
func (n *Node) handlePush(w http.ResponseWriter, r *http.Request) {
	body, sender, err := n.signedBody(w, r, maxPushBody)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var msg pushMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid push"})
		return
	}
	ctx := r.Context()
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !f.cooperating(sender) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this boid does not work with the sender"})
		return
	}
	accepts := func(scanner string) bool {
		return !f.rejects(scanner) && (f.cooperating(scanner) || f.Has(sender))
	}
	reserved := netset.Reserved(n.cfg.AllowPrivate)
	var res pushResult
	var obs []client.Observation
	for _, o := range msg.Observations {
		ip, err := netip.ParseAddr(o.IP)
		switch {
		case err != nil || !n.cfg.Catalog.Contains(ip) || reserved.Contains(ip) || o.SeenAt.After(n.now().Add(maxClockSkew)) || !accepts(o.NodeID):
			res.Rejected++
		case !f.holds(n.cfg.Catalog.Block(ip)) && !f.Has(sender):
			res.Retry = true
		case o.Verify() != nil:
			res.Rejected++
		default:
			obs = append(obs, o)
		}
	}
	var cov []Coverage
	for _, c := range msg.Coverage {
		switch {
		case c.Catalog != n.catalogHash || !n.cfg.Catalog.Valid(c.Unit()) || c.ScannedAt.After(n.now().Add(maxClockSkew)) || !accepts(c.NodeID) || f.peers[c.NodeID].LowReach:
			res.Rejected++
		case !f.holds(c.Block) && !f.Has(sender):
			res.Retry = true
		case !c.Verify():
			res.Rejected++
		default:
			cov = append(cov, c)
		}
	}
	stored, err := n.cfg.Data.AddRemoteObservations(ctx, obs)
	if err == nil {
		var c int
		c, err = n.cfg.Data.AddCoverage(ctx, cov)
		stored += c
	}
	if err != nil {
		slog.Error("storing pushed results", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	res.Stored = stored
	from := sig.Short(sender)
	if p, ok := f.peers[sender]; ok {
		from = p.Label()
	}
	if res.Rejected > 0 {
		slog.Warn("rejected pushed rows: bad signature, reserved address, wrong catalog, or a scanner this boid does not accept", "rejected", res.Rejected, "from", from)
	}
	slog.Debug("push received", "from", from, "observations", len(msg.Observations), "coverage", len(msg.Coverage), "stored", stored, "retry", res.Retry)
	n.sampleRows(ctx, f, obs, cov)
	writeJSON(w, http.StatusOK, res)
}

// Host merges this boid's results for ip with those of the boids holding its block.
func (n *Node) Host(ctx context.Context, ip netip.Addr) (client.Host, error) {
	h := client.Host{IP: ip.String(), Services: []client.Observation{}}
	if excluded, err := n.cfg.Data.Excluded(ctx, ip); err != nil || excluded {
		return h, err
	}
	local, err := n.cfg.Data.Host(ctx, ip)
	if err != nil {
		return h, err
	}
	f, err := n.view(ctx)
	if err != nil {
		return h, err
	}
	var mu sync.Mutex
	all := local.Services
	var wg sync.WaitGroup
	for _, m := range f.Homes(n.cfg.Catalog.Block(ip)) {
		if m.ID == n.cfg.Key.ID() {
			continue
		}
		wg.Go(func() {
			var remote client.Host
			if err := n.call(ctx, http.MethodGet, m.Endpoint+"/api/v1/host/"+ip.String()+"?local=1", nil, &remote); err != nil {
				slog.Debug("host lookup at home failed", "home", m.Label(), "err", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, o := range remote.Services {
				if o.IP == ip.String() && !f.rejects(o.NodeID) && o.Verify() == nil {
					all = append(all, o)
				}
			}
		})
	}
	wg.Wait()
	h.Services = latest(all)
	return h, nil
}

// latest keeps the newest observation per port and module.
func latest(obs []client.Observation) []client.Observation {
	type key struct {
		port int
		name string
	}
	newest := map[key]client.Observation{}
	for _, o := range obs {
		k := key{o.Port, o.Name}
		if cur, ok := newest[k]; !ok || o.SeenAt.After(cur.SeenAt) {
			newest[k] = o
		}
	}
	out := make([]client.Observation, 0, len(newest))
	for _, o := range newest {
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b client.Observation) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// LeaseRequest is signed by the boid that wants to scan a unit.
type LeaseRequest struct {
	Unit      catalog.Unit `json:"unit"`
	Catalog   string       `json:"catalog"`
	Holder    string       `json:"holder"`
	Time      time.Time    `json:"time"`
	Release   bool         `json:"release,omitempty"`
	Signature []byte       `json:"signature"`
}

func (r LeaseRequest) message() []byte {
	action := "acquire"
	if r.Release {
		action = "release"
	}
	return sig.Message("boidscan-lease-v1", r.Unit.Block.String(), strconv.Itoa(r.Unit.Group), r.Catalog, r.Holder, sig.Time(r.Time), action)
}

type leaseResponse struct {
	Granted bool   `json:"granted"`
	TTL     int    `json:"ttl_seconds,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (n *Node) handleLease(w http.ResponseWriter, r *http.Request) {
	var req LeaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid lease request"})
		return
	}
	if !sig.Verify(req.Holder, req.message(), req.Signature) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signature does not match"})
		return
	}
	if d := n.now().Sub(req.Time); d > maxClockSkew || d < -maxClockSkew {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request time too far from this boid's clock"})
		return
	}
	if req.Catalog != n.catalogHash || !n.cfg.Catalog.Valid(req.Unit) {
		writeJSON(w, http.StatusOK, leaseResponse{Reason: "not a unit of this boid's catalog"})
		return
	}
	ctx := r.Context()
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	halt := f.state.Halt(n.now(), n.cfg.Version, n.catalogHash, n.cfg.Key.ID())
	switch {
	case !f.mayLease(req.Holder):
		writeJSON(w, http.StatusOK, leaseResponse{Reason: "this boid does not take scans from the holder"})
		return
	case !f.holds(req.Unit.Block):
		writeJSON(w, http.StatusOK, leaseResponse{Reason: "this boid does not hold the block"})
		return
	case req.Release:
		if err := n.cfg.Data.ReleaseLease(ctx, req.Unit, req.Holder); err != nil {
			slog.Error("releasing lease", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, leaseResponse{})
		return
	case halt != "":
		writeJSON(w, http.StatusOK, leaseResponse{Reason: halt})
		return
	}
	ok, err := n.cfg.Data.AcquireLease(ctx, req.Unit, req.Holder, n.cfg.LeaseTTL, time.Duration(f.state.Latest.MinRescan))
	if err != nil {
		slog.Error("granting lease", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, leaseResponse{Reason: "leased to another boid or scanned recently"})
		return
	}
	slog.Debug("lease granted", "unit", req.Unit.String(), "holder", sig.Short(req.Holder))
	writeJSON(w, http.StatusOK, leaseResponse{Granted: true, TTL: int(n.cfg.LeaseTTL.Seconds())})
}

// dueUnits are the stalest units id holds that are not leased and were not
// scanned within minRescan. Never-scanned units come first, group 0 before group 1.
func dueUnits(cat catalog.Catalog, v View, id string, status []UnitStatus, skip *netset.Set, minRescan time.Duration, now time.Time, limit int) []catalog.Unit {
	last := map[catalog.Unit]time.Time{}
	leased := map[catalog.Unit]bool{}
	for _, s := range status {
		if s.ScannedAt.After(last[s.Unit]) {
			last[s.Unit] = s.ScannedAt
		}
		if s.LeasedBy != "" {
			leased[s.Unit] = true
		}
	}
	type cand struct {
		u catalog.Unit
		t time.Time
	}
	var cands []cand
	blocks := cat.Blocks(skip)
	// Boids holding the same block should not all reach for the same unit.
	rand.Shuffle(len(blocks), func(i, j int) { blocks[i], blocks[j] = blocks[j], blocks[i] })
	for _, b := range blocks {
		if !v.IsHome(b, id) {
			continue
		}
		for g := range cat.Groups {
			u := catalog.Unit{Block: b, Group: g}
			t := last[u]
			if leased[u] || (!t.IsZero() && now.Sub(t) < minRescan) {
				continue
			}
			cands = append(cands, cand{u, t})
		}
	}
	slices.SortStableFunc(cands, func(a, b cand) int {
		return cmp.Or(a.t.Compare(b.t), cmp.Compare(a.u.Group, b.u.Group))
	})
	out := make([]catalog.Unit, 0, min(limit, len(cands)))
	for _, c := range cands[:min(limit, len(cands))] {
		out = append(out, c.u)
	}
	return out
}

func (n *Node) handleDue(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	limit = min(max(limit, 1), 64)
	ctx := r.Context()
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if f.state.Halt(n.now(), n.cfg.Version, n.catalogHash, n.cfg.Key.ID()) != "" {
		writeJSON(w, http.StatusOK, []catalog.Unit{})
		return
	}
	status, err := n.cfg.Data.UnitStatus(ctx)
	if err != nil {
		slog.Error("loading unit status", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	units := dueUnits(n.cfg.Catalog, f.View, n.cfg.Key.ID(), status, netset.Reserved(n.cfg.AllowPrivate), time.Duration(f.state.Latest.MinRescan), n.now(), limit)
	writeJSON(w, http.StatusOK, units)
}

// handleUnits lists the units this boid holds that were scanned or are leased.
func (n *Node) handleUnits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	status, err := n.cfg.Data.UnitStatus(ctx)
	if err != nil {
		slog.Error("loading unit status", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	out := []UnitStatus{}
	for _, s := range status {
		if f.IsHome(s.Block, n.cfg.Key.ID()) {
			out = append(out, s)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (n *Node) handleRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := n.cfg.Data.SweepRuns(r.Context(), 1000)
	if err != nil {
		slog.Error("loading runs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if runs == nil {
		runs = []Run{}
	}
	writeJSON(w, http.StatusOK, runs)
}

type homesView struct {
	Block netip.Prefix `json:"block"`
	Homes []Member     `json:"homes"`
}

func (n *Node) handleHomes(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil || !ip.Unmap().Is4() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "want ?ip=<IPv4 address>"})
		return
	}
	f, err := n.view(r.Context())
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	block := n.cfg.Catalog.Block(ip)
	writeJSON(w, http.StatusOK, homesView{Block: block, Homes: f.Homes(block)})
}

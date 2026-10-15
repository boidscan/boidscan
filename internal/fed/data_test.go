package fed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

type memLease struct {
	holder  string
	expires time.Time
}

// memData keeps a boid's results in memory, with the semantics of the Postgres store.
type memData struct {
	mu          sync.Mutex
	now         func() time.Time
	obs         []client.Observation
	cov         []Coverage
	leases      map[catalog.Unit]memLease
	replicas    map[string]ReplicaState
	runs        []Run
	excluded    netset.Set
	trust       memTrust
	optOuts     []OptOut
	cursors     map[string]time.Time
	optOutReads int
	optOutID    int64
	progress    map[string]memProgress
}

type memProgress struct {
	at time.Time
	sp SignedProgress
}

func newMemData(now func() time.Time) *memData {
	return &memData{now: now, leases: map[catalog.Unit]memLease{}, replicas: map[string]ReplicaState{}, progress: map[string]memProgress{}, cursors: map[string]time.Time{}}
}

func (m *memData) Host(_ context.Context, ip netip.Addr) (client.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var found []client.Observation
	for _, o := range m.obs {
		if o.IP == ip.String() {
			found = append(found, o)
		}
	}
	return client.Host{IP: ip.String(), Services: latest(found)}, nil
}

func (m *memData) serveHost(w http.ResponseWriter, r *http.Request) {
	ip := netip.MustParseAddr(strings.TrimPrefix(r.URL.Path, "/api/v1/host/"))
	h, _ := m.Host(r.Context(), ip)
	if len(h.Services) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no data for this host"})
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (m *memData) Excluded(_ context.Context, ip netip.Addr) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.excluded.Contains(ip) || m.optedOut(ip), nil
}

func (m *memData) RangeExclusions(context.Context) (*netset.Set, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &netset.Set{}
	s.AddSet(&m.excluded)
	return s, nil
}

func (m *memData) ExclusionSet(_ context.Context, within []netip.Prefix) (*netset.Set, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &netset.Set{}
	for _, w := range within {
		for _, p := range m.excluded.Prefixes() {
			if p.Overlaps(w) {
				s.Add(p)
			}
		}
		for _, o := range m.activeOptOuts() {
			if w.Contains(o.IP) {
				s.Add(netip.PrefixFrom(o.IP, 32))
			}
		}
	}
	return s, nil
}

func (m *memData) ObservationsAfter(_ context.Context, after int64, limit int) ([]client.Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []client.Observation
	for _, o := range m.obs {
		if o.ID > after && len(out) < limit {
			out = append(out, o)
		}
	}
	return out, nil
}

func (m *memData) CoverageAfter(_ context.Context, after int64, limit int) ([]Coverage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Coverage
	for _, c := range m.cov {
		if c.ID > after && len(out) < limit {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memData) AddRemoteObservations(_ context.Context, obs []client.Observation) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range obs {
		ip := netip.MustParseAddr(o.IP)
		if m.excluded.Contains(ip) || m.optedOut(ip) || slices.ContainsFunc(m.obs, func(x client.Observation) bool { return bytes.Equal(x.Signature, o.Signature) }) {
			continue
		}
		o.ID = int64(len(m.obs) + 1)
		m.obs = append(m.obs, o)
		n++
	}
	return n, nil
}

func (m *memData) AddCoverage(_ context.Context, cov []Coverage) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range cov {
		if l, ok := m.leases[c.Unit()]; ok && l.holder == c.NodeID {
			delete(m.leases, c.Unit())
		}
		if slices.ContainsFunc(m.cov, func(x Coverage) bool { return bytes.Equal(x.Signature, c.Signature) }) {
			continue
		}
		c.ID = int64(len(m.cov) + 1)
		m.cov = append(m.cov, c)
		n++
	}
	return n, nil
}

func (m *memData) ReplicaState(_ context.Context, home string) (ReplicaState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.replicas[home], nil
}

func (m *memData) SaveReplicaState(_ context.Context, home string, s ReplicaState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.View, s.Old = slices.Clone(s.View), slices.Clone(s.Old)
	m.replicas[home] = s
	return nil
}

func (m *memData) AcquireLease(_ context.Context, u catalog.Unit, holder string, ttl, minRescan time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, c := range m.cov {
		if c.Unit() == u && c.ScannedAt.After(now.Add(-minRescan)) {
			return false, nil
		}
	}
	if l, ok := m.leases[u]; ok && l.holder != holder && l.expires.After(now) {
		return false, nil
	}
	m.leases[u] = memLease{holder, now.Add(ttl)}
	return true, nil
}

func (m *memData) ReleaseLease(_ context.Context, u catalog.Unit, holder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leases[u].holder == holder {
		delete(m.leases, u)
	}
	return nil
}

func (m *memData) UnitStatus(_ context.Context, blocks []netip.Prefix) ([]UnitStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byUnit := map[catalog.Unit]*UnitStatus{}
	get := func(u catalog.Unit) *UnitStatus {
		if byUnit[u] == nil {
			byUnit[u] = &UnitStatus{Unit: u}
		}
		return byUnit[u]
	}
	for _, c := range m.cov {
		if s := get(c.Unit()); c.ScannedAt.After(s.ScannedAt) {
			s.ScannedAt, s.ScannedBy = c.ScannedAt, c.NodeID
		}
	}
	for u, l := range m.leases {
		if l.expires.After(m.now()) {
			get(u).LeasedBy = l.holder
		}
	}
	var out []UnitStatus
	for _, s := range byUnit {
		if slices.Contains(blocks, s.Block) {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *memData) SweepRuns(context.Context, int) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.runs), nil
}

func (m *memData) RecentRun(_ context.Context, u catalog.Unit, d time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if r.Unit == u && r.StartedAt.After(m.now().Add(-d)) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memData) HostCounts(_ context.Context, blocks []netip.Prefix) (map[netip.Prefix]HostCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type port struct {
		ip   netip.Addr
		port int
	}
	hosts, ports := map[netip.Addr]bool{}, map[port]bool{}
	out := map[netip.Prefix]HostCount{}
	for _, o := range m.obs {
		ip := netip.MustParseAddr(o.IP)
		i := slices.IndexFunc(blocks, func(b netip.Prefix) bool { return b.Contains(ip) })
		if i < 0 {
			continue
		}
		b := blocks[i]
		c := out[b]
		if !hosts[ip] {
			hosts[ip] = true
			c.Hosts++
		}
		if !ports[port{ip, o.Port}] {
			ports[port{ip, o.Port}] = true
			c.OpenPorts++
		}
		out[b] = c
	}
	return out, nil
}

func (m *memData) SaveProgress(_ context.Context, id string, at time.Time, sp SignedProgress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.progress[id]; !ok || at.After(cur.at) {
		m.progress[id] = memProgress{at, sp}
	}
	return nil
}

func (m *memData) Progress(context.Context) ([]SignedProgress, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SignedProgress
	for _, p := range m.progress {
		out = append(out, p.sp)
	}
	return out, nil
}

func (m *memData) has(ip string) bool {
	h, _ := m.Host(context.Background(), netip.MustParseAddr(ip))
	return len(h.Services) > 0
}

func signedObservation(k Signer, ip string, port int, at time.Time) client.Observation {
	o := client.Observation{NodeID: k.ID(), IP: ip, Port: port, Name: "ssh" + strconv.Itoa(port), Protocol: "ssh", Status: "success",
		SeenAt: at.UTC().Truncate(time.Microsecond), Data: json.RawMessage(`{"status":"success"}`)}
	o.Signature = k.Sign(sig.ObservationMessage(o.IP, o.Port, o.Name, o.Protocol, o.Status, o.SeenAt, o.Data))
	return o
}

// labCatalog keeps two homes per block, so three test boids have blocks
// that one of them does not hold.
var labCatalog = func() catalog.Catalog {
	c, _ := catalog.Lab(netip.MustParsePrefix("172.30.0.0/26"))
	c.Replicas = 2
	return c
}()

func newDataBoid(t *testing.T, name string, clk *clock, seeds ...string) *testBoid {
	b := newBoid(t, name, clk, seeds...)
	b.data = newMemData(clk.now)
	b.cfg.Catalog = labCatalog
	b.catalogHash = labCatalog.Hash()
	b.cfg.Data = b.data
	b.cfg.AllowPrivate = true
	b.cfg.LeaseTTL = 30 * time.Second
	b.store.data = b.data
	b.data.trust.peers = b.store
	b.cfg.Trust = LabTrust()
	b.install(t, testPolicy(t, 1, clk.now(), nil))
	return b
}

func (b *testBoid) currentView(t *testing.T) View {
	t.Helper()
	f, err := b.view(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return f.View
}

func byID(boids []*testBoid) map[string]*testBoid {
	m := map[string]*testBoid{}
	for _, b := range boids {
		m[b.cfg.Key.ID()] = b
	}
	return m
}

func TestPlacement(t *testing.T) {
	var ids []string
	for i := range 10 {
		ids = append(ids, fmt.Sprintf("node-%d", i))
	}
	blocks := catalog.Default().Blocks(nil)[:2000]
	shuffled := slices.Clone(ids)
	slices.Reverse(shuffled)
	moved := 0
	for _, b := range blocks {
		before := homes(b, ids, 3)
		if !slices.Equal(before, homes(b, shuffled, 3)) {
			t.Fatalf("placement of %s depends on member order", b)
		}
		after := homes(b, append(slices.Clone(ids), "node-new"), 3)
		if slices.Equal(before, after) {
			continue
		}
		moved++
		kept := 0
		for _, id := range after {
			if slices.Contains(before, id) {
				kept++
			}
		}
		if !slices.Contains(after, "node-new") || kept != 2 {
			t.Fatalf("%s moved from %v to %v; only the newcomer may take one place", b, before, after)
		}
	}
	// A newcomer should win about 3 of 11 places.
	if frac := float64(moved) / float64(len(blocks)); frac < 0.2 || frac > 0.35 {
		t.Fatalf("%.2f of the blocks moved", frac)
	}
}

func TestDueUnits(t *testing.T) {
	now := time.Now()
	self := Member{ID: "self"}
	v := NewView(self, nil, labCatalog, nil)
	fresh := catalog.Unit{Block: netip.MustParsePrefix("172.30.0.0/30"), Group: 0}
	stale := catalog.Unit{Block: netip.MustParsePrefix("172.30.0.4/30"), Group: 0}
	leased := catalog.Unit{Block: netip.MustParsePrefix("172.30.0.8/30"), Group: 1}
	status := []UnitStatus{
		{Unit: fresh, ScannedAt: now.Add(-time.Minute)},
		{Unit: stale, ScannedAt: now.Add(-2 * time.Hour)},
		{Unit: leased, LeasedBy: "other"},
	}
	due := dueUnits(labCatalog, heldBlocks(labCatalog, v, "self", nil), status, time.Hour, now, 100)
	if len(due) != 30 {
		t.Fatalf("%d units due, want 30", len(due))
	}
	if slices.Contains(due, fresh) || slices.Contains(due, leased) {
		t.Fatal("a fresh or leased unit is due")
	}
	for i, u := range due[:29] {
		if want := min(i/14, 1); u.Group != want {
			t.Fatalf("unit %d is %v: never-scanned units come first, group 0 before group 1", i, u)
		}
	}
	if due[29] != stale {
		t.Fatalf("last due unit is %v, want the stale one", due[29])
	}
	if got := dueUnits(labCatalog, heldBlocks(labCatalog, v, "someone-else", nil), status, time.Hour, now, 100); len(got) != 0 {
		t.Fatalf("units due for a boid that holds nothing: %v", got)
	}
}

// replicated checks that every home in viewer's view holds ip.
func replicated(t *testing.T, viewer *testBoid, boids []*testBoid, ip string) {
	t.Helper()
	all := byID(boids)
	for _, h := range viewer.currentView(t).Homes(labCatalog.Block(netip.MustParseAddr(ip))) {
		if !all[h.ID].data.has(ip) {
			t.Errorf("%s is a home of %s but does not hold it", h.Name, ip)
		}
	}
}

func TestReplication(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)

	var ips []string
	for i := range 16 {
		ip := fmt.Sprintf("172.30.0.%d", i*4+1)
		ips = append(ips, ip)
		a.data.AddRemoteObservations(context.Background(), []client.Observation{signedObservation(a.cfg.Key, ip, 22, clk.now())})
	}
	u := catalog.Unit{Block: netip.MustParsePrefix("172.30.0.8/30")}
	a.data.AddCoverage(context.Background(), []Coverage{SignCoverage(a.cfg.Key, u, a.catalogHash, clk.now())})
	a.Replicate(context.Background())

	v := a.currentView(t)
	for _, ip := range ips {
		homes := v.Homes(labCatalog.Block(netip.MustParseAddr(ip)))
		for _, x := range boids[1:] {
			isHome := slices.ContainsFunc(homes, func(m Member) bool { return m.ID == x.cfg.Key.ID() })
			if x.data.has(ip) != isHome {
				t.Errorf("%s holds %s: %v, is a home: %v", x.cfg.Name, ip, x.data.has(ip), isHome)
			}
		}
	}
	for _, h := range v.Homes(u.Block) {
		if h.ID != a.cfg.Key.ID() && len(byID(boids)[h.ID].data.cov) != 1 {
			t.Errorf("coverage of %v did not reach %s", u, h.Name)
		}
	}

	// boid-d joins while boid-a is offline, then boid-a goes down: the blocks
	// boid-a held move to the others, who pass them on.
	a.offline.Store(true)
	d := newDataBoid(t, "boid-d", clk, b.srv.URL)
	live := []*testBoid{b, c, d}
	rounds(live, 3)
	for range downAfter + 1 {
		clk.advance(time.Second)
		rounds(live, 1)
		for _, x := range live {
			x.Replicate(context.Background())
		}
	}
	for _, x := range live {
		if x.currentView(t).Has(a.cfg.Key.ID()) {
			t.Fatalf("boid-a is still in the view of %s", x.cfg.Name)
		}
	}
	for _, ip := range ips {
		replicated(t, d, live, ip)
	}
}

func TestPushRejects(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	rounds([]*testBoid{a, b}, 2)

	tampered := signedObservation(a.cfg.Key, "172.30.0.5", 22, clk.now())
	tampered.Data = json.RawMessage(`{"status":"forged"}`)
	public := signedObservation(a.cfg.Key, "8.8.8.8", 22, clk.now())
	otherCatalog := SignCoverage(a.cfg.Key, catalog.Unit{Block: netip.MustParsePrefix("172.30.0.8/30")}, "other", clk.now())
	res := push(t, a, b, pushMsg{Observations: []client.Observation{tampered, public}, Coverage: []Coverage{otherCatalog}})
	if res.Rejected != 3 || res.Stored != 0 || res.Retry {
		t.Fatalf("push = %+v, want all rejected", res)
	}
	good := signedObservation(a.cfg.Key, "172.30.0.5", 22, clk.now())
	if res := push(t, a, b, pushMsg{Observations: []client.Observation{good, good}}); res.Stored != 1 {
		t.Fatalf("push = %+v, want the duplicate skipped", res)
	}
}

func push(t *testing.T, from, to *testBoid, msg pushMsg) pushResult {
	t.Helper()
	body, _ := json.Marshal(msg)
	var res pushResult
	if err := from.signedCall(context.Background(), http.MethodPost, to.srv.URL+"/fed/v1/push", body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHostRouting(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)

	ip := "172.30.0.11"
	homes := a.currentView(t).Homes(labCatalog.Block(netip.MustParseAddr(ip)))
	var viewer *testBoid
	for _, x := range boids {
		if !slices.ContainsFunc(homes, func(m Member) bool { return m.ID == x.cfg.Key.ID() }) {
			viewer = x
		}
	}
	all := byID(boids)
	first, second := all[homes[0].ID], all[homes[1].ID]
	old := signedObservation(first.cfg.Key, ip, 22, clk.now().Add(-time.Hour))
	newer := signedObservation(first.cfg.Key, ip, 22, clk.now())
	first.data.AddRemoteObservations(context.Background(), []client.Observation{old})
	second.data.AddRemoteObservations(context.Background(), []client.Observation{newer})
	forged := signedObservation(first.cfg.Key, ip, 80, clk.now())
	forged.Port = 81
	second.data.AddRemoteObservations(context.Background(), []client.Observation{forged})

	h, err := viewer.Host(context.Background(), netip.MustParseAddr(ip))
	if err != nil || len(h.Services) != 1 || !h.Services[0].SeenAt.Equal(newer.SeenAt) {
		t.Fatalf("Host = %+v, %v; want only the newest signed result", h, err)
	}
	second.offline.Store(true)
	if h, _ := viewer.Host(context.Background(), netip.MustParseAddr(ip)); len(h.Services) != 1 {
		t.Fatalf("with one home offline Host = %+v", h)
	}
	viewer.data.excluded.Add(netip.MustParsePrefix(ip + "/32"))
	if h, _ := viewer.Host(context.Background(), netip.MustParseAddr(ip)); len(h.Services) != 0 {
		t.Fatalf("an excluded address was served: %+v", h)
	}
}

func newTestSweeper(b *testBoid, clk *clock, scanned func(*testBoid, catalog.Unit)) *Sweeper {
	s := NewSweeper(SweepConfig{
		Key:          b.cfg.Key,
		Name:         b.cfg.Name,
		Endpoint:     b.srv.URL,
		Catalog:      labCatalog,
		RootID:       testRoot.ID(),
		Version:      b.cfg.Version,
		AllowPrivate: true,
		Scan: func(_ context.Context, u catalog.Unit, _ int) error {
			b.data.mu.Lock()
			b.data.runs = append(b.data.runs, Run{Unit: u, StartedAt: clk.now()})
			b.data.mu.Unlock()
			scanned(b, u)
			return nil
		},
	}, struct {
		*memStore
		*memData
	}{b.store, b.data})
	s.now = clk.now
	return s
}

func TestLeases(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	rounds([]*testBoid{a, b, c}, 2)
	sa := newTestSweeper(a, clk, nil)
	sb := newTestSweeper(b, clk, nil)

	u := catalog.Unit{Block: netip.MustParsePrefix("172.30.0.8/30"), Group: 1}
	homes := a.currentView(t).Homes(u.Block)
	ctx := context.Background()
	if granted, ttl := sa.request(ctx, u, homes, false); len(granted) != 2 || ttl != 30*time.Second {
		t.Fatalf("first lease: granted by %d homes for %s", len(granted), ttl)
	}
	if granted, _ := sb.request(ctx, u, homes, false); len(granted) != 0 {
		t.Fatalf("a leased unit was granted again by %d homes", len(granted))
	}
	if granted, _ := sa.request(ctx, u, homes, false); len(granted) != 2 {
		t.Fatal("the holder could not renew its lease")
	}
	sa.request(ctx, u, homes, true)
	if granted, _ := sb.request(ctx, u, homes, false); len(granted) != 2 {
		t.Fatal("a released unit could not be leased")
	}
	clk.advance(31 * time.Second)
	if granted, _ := sa.request(ctx, u, homes, false); len(granted) != 2 {
		t.Fatal("an expired lease still blocks the unit")
	}

	forged := LeaseRequest{Unit: u, Catalog: a.catalogHash, Holder: b.cfg.Key.ID(), Time: clk.now()}
	forged.Signature = a.cfg.Key.Sign(forged.message())
	body, _ := json.Marshal(forged)
	res, err := http.Post(homes[0].Endpoint+"/fed/v1/lease", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a lease request signed by another key got %s", res.Status)
	}
}

// TestSweep runs the whole flock's sweep: every unit is scanned exactly once.
func TestSweep(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)

	var mu sync.Mutex
	count := map[catalog.Unit]int{}
	stole := 0
	scanned := func(x *testBoid, u catalog.Unit) {
		mu.Lock()
		defer mu.Unlock()
		count[u]++
		if !x.currentView(t).IsHome(u.Block, x.cfg.Key.ID()) {
			stole++
		}
	}
	var sweepers []*Sweeper
	for _, x := range boids {
		sweepers = append(sweepers, newTestSweeper(x, clk, scanned))
	}
	ctx := context.Background()
	for round := 0; ; round++ {
		if round > 100 {
			t.Fatal("the sweep does not end")
		}
		found := false
		for _, s := range sweepers {
			ok, err := s.Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found = found || ok
		}
		for _, x := range boids {
			x.Replicate(ctx)
		}
		if !found {
			break
		}
	}
	units := len(labCatalog.Blocks(nil)) * len(labCatalog.Groups)
	if len(count) != units {
		t.Fatalf("%d of %d units scanned", len(count), units)
	}
	for u, n := range count {
		if n != 1 {
			t.Errorf("%v scanned %d times", u, n)
		}
	}
	t.Logf("%d units, %d taken from other boids' blocks", units, stole)
}

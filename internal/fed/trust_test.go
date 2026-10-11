package fed

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

func vote(checker string, open bool, fp string) Vote {
	return Vote{Checker: checker, CheckResult: CheckResult{Open: open, Fingerprint: fp}}
}

func TestVerdict(t *testing.T) {
	obs := Sample{Kind: KindObservation, Scanner: "s", ReportedOpen: true, ReportedFP: "aa"}
	cov := Sample{Kind: KindCoverage, Scanner: "s"}
	gone := Vote{Checker: "c", CheckResult: CheckResult{Unavailable: true}}
	for name, c := range map[string]struct {
		s     Sample
		votes []Vote
		want  string
	}{
		"confirmed":                     {obs, []Vote{vote("a", true, "aa"), vote("b", true, "aa")}, VerdictPass},
		"no fingerprint to compare":     {obs, []Vote{vote("a", true, ""), vote("b", true, "")}, VerdictPass},
		"one checker is not a quorum":   {obs, []Vote{vote("a", false, ""), vote("s", true, "aa"), gone}, VerdictInconclusive},
		"checkers disagree":             {obs, []Vote{vote("a", false, ""), vote("b", true, "aa")}, VerdictInconclusive},
		"one checker blocked":           {obs, []Vote{vote("a", false, ""), vote("b", true, "aa"), vote("c", true, "aa")}, VerdictPass},
		"closed, scanner sees it too":   {obs, []Vote{vote("a", false, ""), vote("b", false, ""), vote("s", false, "")}, VerdictChange},
		"closed, scanner insists":       {obs, []Vote{vote("a", false, ""), vote("b", false, ""), vote("s", true, "aa")}, VerdictUnconfirmed},
		"closed, scanner silent":        {obs, []Vote{vote("a", false, ""), vote("b", false, "")}, VerdictUnconfirmed},
		"other server, scanner agrees":  {obs, []Vote{vote("a", true, "bb"), vote("b", true, "bb"), vote("s", true, "bb")}, VerdictChange},
		"other server, scanner lies":    {obs, []Vote{vote("a", true, "bb"), vote("b", true, "bb"), vote("s", true, "aa")}, VerdictContradicted},
		"coverage, closed for all":      {cov, []Vote{vote("a", false, ""), vote("b", false, "")}, VerdictPass},
		"coverage, scanner sees it now": {cov, []Vote{vote("a", true, "aa"), vote("b", true, "aa"), vote("s", true, "aa")}, VerdictChange},
		"coverage, scanner blocked":     {cov, []Vote{vote("a", true, "aa"), vote("b", true, "aa"), vote("s", false, "")}, VerdictMissed},
	} {
		if got := verdict(c.s, c.votes); got != c.want {
			t.Errorf("%s: verdict = %s, want %s", name, got, c.want)
		}
	}
}

func TestAssess(t *testing.T) {
	c := DefaultTrust()
	for name, tc := range map[string]struct {
		cur   string
		s     Score
		trust string
		low   bool
	}{
		"new":                     {TrustProbation, Score{Pass: 3}, TrustProbation, false},
		"earned":                  {TrustProbation, Score{Pass: 20}, TrustTrusted, false},
		"some contradictions":     {TrustTrusted, Score{Pass: 40, Contradicted: 3}, TrustTrusted, false},
		"many contradictions":     {TrustTrusted, Score{Pass: 20, Contradicted: 3}, TrustShunned, false},
		"blocked by a few":        {TrustTrusted, Score{Pass: 30, Unconfirmed: 4}, TrustTrusted, false},
		"mostly unconfirmed":      {TrustProbation, Score{Pass: 4, Unconfirmed: 6}, TrustShunned, false},
		"misses a lot":            {TrustTrusted, Score{Pass: 25, Missed: 5, CoverageDecided: 10}, TrustTrusted, true},
		"misses little":           {TrustTrusted, Score{Pass: 25, Missed: 2, CoverageDecided: 10}, TrustTrusted, false},
		"shunning stays":          {TrustShunned, Score{Pass: 100}, TrustShunned, false},
		"too few coverage checks": {TrustProbation, Score{Missed: 5, CoverageDecided: 5}, TrustProbation, false},
	} {
		trust, low := c.Assess(tc.cur, tc.s)
		if trust != tc.trust || low != tc.low {
			t.Errorf("%s: Assess = %s, low reach %v; want %s, %v", name, trust, low, tc.trust, tc.low)
		}
	}
}

func TestHomeEligible(t *testing.T) {
	all := func(Peer) bool { return true }
	peers := []Peer{{Record: Record{ID: "a"}, Trust: TrustTrusted}, {Record: Record{ID: "b"}, Trust: TrustProbation}, {Record: Record{ID: "c"}, Trust: TrustShunned}}
	keep := homeEligible(peers, 3, all)
	if !keep(peers[0]) || !keep(peers[1]) || keep(peers[2]) {
		t.Fatal("a boid that trusts too few peers must use every peer it has not shunned")
	}
	peers = append(peers, Peer{Record: Record{ID: "d"}, Trust: TrustTrusted})
	keep = homeEligible(peers, 3, all)
	if !keep(peers[0]) || keep(peers[1]) || !keep(peers[3]) {
		t.Fatal("with enough trusted peers, peers on probation must not be homes")
	}
}

// world is the lab network as each boid sees it: some boids are blocked.
type world struct {
	mu      sync.Mutex
	open    map[CheckTarget]string
	blocked map[string]bool
}

func (w *world) checker(b *testBoid) func(context.Context, []CheckTarget) ([]CheckResult, error) {
	return func(_ context.Context, targets []CheckTarget) ([]CheckResult, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		out := make([]CheckResult, len(targets))
		for i, t := range targets {
			if fp, ok := w.open[t]; ok && !w.blocked[b.cfg.Key.ID()] {
				out[i] = CheckResult{Open: true, Fingerprint: fp}
			}
		}
		return out, nil
	}
}

func observationOf(k Signer, t CheckTarget, fp string, at time.Time) client.Observation {
	o := signedObservation(k, t.IP.String(), int(t.Port), at)
	o.Name = t.Name
	o.Data = []byte(`{"result":{"key_exchange":{"server_host_key":{"fingerprint_sha256":"` + fp + `"}}}}`)
	o.Signature = k.Sign(sig.ObservationMessage(o.IP, o.Port, o.Name, o.Protocol, o.Status, o.SeenAt, o.Data))
	return o
}

// settle runs sampling to its verdicts: requests, grabs, collection.
func settle(boids []*testBoid) {
	ctx := context.Background()
	for range 4 {
		for _, b := range boids {
			b.AdvanceSamples(ctx)
		}
		for _, b := range boids {
			b.RunChecks(ctx)
		}
	}
}

func TestForgerAndBlockedBoid(t *testing.T) {
	clk := &clock{t: time.Now()}
	// Many blocks, so one is surely held by the three honest boids alone.
	five, _ := catalog.Lab(netip.MustParsePrefix("172.30.0.0/22"))
	w := &world{open: map[CheckTarget]string{}, blocked: map[string]bool{}}
	var boids []*testBoid
	for _, name := range []string{"boid-a", "boid-b", "boid-c", "boid-d", "boid-e"} {
		var seeds []string
		if len(boids) > 0 {
			seeds = []string{boids[0].srv.URL}
		}
		b := newDataBoid(t, name, clk, seeds...)
		b.cfg.Catalog, b.catalogHash = five, five.Hash()
		b.store.policies = nil
		b.install(t, testPolicy(t, 1, clk.now(), func(p *flockpolicy.Body) { p.Catalog = five.Hash() }))
		b.cfg.Check = w.checker(b)
		boids = append(boids, b)
	}
	a, d, e := boids[0], boids[3], boids[4]
	e.cfg.Forge = true
	w.blocked[d.cfg.Key.ID()] = true
	rounds(boids, 3)

	// A block held by the three honest boids, so each result has two homes to check it.
	var block netip.Prefix
	var homes []Member
	for _, b := range five.Blocks(nil) {
		homes = a.currentView(t).Homes(b)
		if !slices.ContainsFunc(homes, func(m Member) bool { return m.ID == d.cfg.Key.ID() || m.ID == e.cfg.Key.ID() }) {
			block = b
			break
		}
	}
	host := block.Addr().Next()
	ssh := CheckTarget{IP: host, Port: 22, Name: "ssh22"}
	https := CheckTarget{IP: host.Next(), Port: 443, Name: "https443"}
	phantom := CheckTarget{IP: host.Next().Next(), Port: 443, Name: "https443"}
	w.open[ssh], w.open[https] = "aa", "bb"
	ctx := context.Background()

	// boid-a reports what is there; the homes confirm it.
	clk.advance(time.Second)
	a.data.AddRemoteObservations(ctx, []client.Observation{observationOf(a.cfg.Key, ssh, "aa", clk.now()), observationOf(a.cfg.Key, https, "bb", clk.now())})
	a.Replicate(ctx)
	settle(boids)

	// boid-e reports other servers and one that does not exist, and defends them.
	e.data.AddRemoteObservations(ctx, []client.Observation{
		observationOf(e.cfg.Key, ssh, "ff", clk.now()), observationOf(e.cfg.Key, https, "ff", clk.now()), observationOf(e.cfg.Key, phantom, "ff", clk.now()),
	})
	e.Replicate(ctx)
	settle(boids)

	// boid-d is blocked by the targets: three times it reports the block empty.
	for range 3 {
		clk.advance(time.Minute)
		d.data.AddCoverage(ctx, []Coverage{SignCoverage(d.cfg.Key, catalog.Unit{Block: block}, five.Hash(), clk.now())})
	}
	d.Replicate(ctx)
	settle(boids)

	byID := byID(boids)
	checked := 0
	for _, m := range homes {
		h := byID[m.ID]
		if h == e || h == d {
			continue
		}
		checked++
		peers := peerByName(h)
		if p := peers["boid-e"]; p.Trust != TrustShunned {
			t.Errorf("%s: boid-e is %s, want shunned", h.cfg.Name, p.Trust)
		}
		if p := peers["boid-d"]; !p.LowReach || p.Trust == TrustShunned {
			t.Errorf("%s: boid-d has low reach %v and is %s; want low reach, not shunned", h.cfg.Name, p.LowReach, p.Trust)
		}
		if h != a && peers["boid-a"].Trust != TrustTrusted {
			t.Errorf("%s: boid-a is %s, want trusted", h.cfg.Name, peers["boid-a"].Trust)
		}
		for _, o := range h.data.obs {
			if o.NodeID == e.cfg.Key.ID() {
				t.Errorf("%s still holds a result of the shunned boid: %s:%d", h.cfg.Name, o.IP, o.Port)
			}
		}
		if slices.ContainsFunc(h.data.cov, func(c Coverage) bool { return c.NodeID == d.cfg.Key.ID() }) {
			t.Errorf("%s still counts the coverage of the blocked boid", h.cfg.Name)
		}
		if res := leaseReason(t, d, h, catalog.Unit{Block: block}); res.Granted {
			t.Errorf("%s granted a lease to the blocked boid", h.cfg.Name)
		}
		if h.currentView(t).Has(e.cfg.Key.ID()) {
			t.Errorf("boid-e is still a possible home for %s", h.cfg.Name)
		}
	}
	if checked != 3 {
		t.Fatalf("%d honest homes of %s checked, want 3", checked, block)
	}
}

func peerByName(b *testBoid) map[string]Peer {
	peers, _ := b.store.Peers(context.Background())
	out := map[string]Peer{}
	for _, p := range peers {
		out[p.Name] = p
	}
	return out
}

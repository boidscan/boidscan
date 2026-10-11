package fed

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

func (b *testBoid) serial() uint64 {
	st, _ := b.store.PolicyState(context.Background())
	return st.Serial()
}

func (b *testBoid) forgetPolicy() {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	b.store.policies, b.store.pause = nil, nil
}

func leaseReason(t *testing.T, from, home *testBoid, u catalog.Unit) leaseResponse {
	t.Helper()
	req := LeaseRequest{Unit: u, Catalog: from.catalogHash, Holder: from.cfg.Key.ID(), Time: from.now()}
	req.Signature = from.cfg.Key.Sign(req.message())
	body, _ := json.Marshal(req)
	var res leaseResponse
	if err := call(context.Background(), home.srv.Client(), http.MethodPost, home.srv.URL+"/fed/v1/lease", body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// homeUnit is a unit that home holds.
func homeUnit(t *testing.T, home *testBoid) catalog.Unit {
	t.Helper()
	v := home.currentView(t)
	for _, b := range labCatalog.Blocks(nil) {
		if v.IsHome(b, home.cfg.Key.ID()) {
			return catalog.Unit{Block: b}
		}
	}
	t.Fatal("home holds no block")
	return catalog.Unit{}
}

func TestNoPolicyNoSweep(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	a.forgetPolicy()
	b.forgetPolicy()
	rounds([]*testBoid{a, b}, 2)

	if got := len(a.currentView(t).IDs()); got != 2 {
		t.Fatalf("boids without a policy must still share data: view of %d", got)
	}
	if found, err := newTestSweeper(b, clk, func(*testBoid, catalog.Unit) { t.Error("scanned without a policy") }).Step(context.Background()); found || err != nil {
		t.Fatalf("Step = %v, %v", found, err)
	}
	if res := leaseReason(t, b, a, homeUnit(t, a)); res.Granted || !strings.Contains(res.Reason, "no flock policy") {
		t.Fatalf("lease without a policy: %+v", res)
	}
}

func TestPolicySpreads(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	b.forgetPolicy()
	c.forgetPolicy()
	rounds(boids, 4)
	for _, x := range boids {
		if x.serial() != 1 {
			t.Fatalf("%s holds policy %d, want 1 from boid-a", x.cfg.Name, x.serial())
		}
	}

	a.install(t, testPolicy(t, 2, clk.now(), func(b *flockpolicy.Body) { b.Pause = true }))
	clk.advance(time.Second)
	rounds(boids, 3)
	for _, x := range boids {
		if x.serial() != 2 {
			t.Fatalf("%s holds policy %d, want 2", x.cfg.Name, x.serial())
		}
	}
	if found, _ := newTestSweeper(c, clk, func(*testBoid, catalog.Unit) { t.Error("scanned while paused") }).Step(context.Background()); found {
		t.Fatal("a paused flock swept")
	}

	// A boid that claims a newer policy it cannot show is not trusted and changes nothing.
	evil := newDataBoid(t, "evil", clk, a.srv.URL)
	forger, _ := identity.Generate()
	forged := testPolicy(t, 9, clk.now(), nil)
	forged.Signatures = nil
	forged.Sign(forger)
	p, _ := flockpolicy.Parse(forged)
	evil.store.policies = append(evil.store.policies, p)
	clk.advance(time.Second)
	rounds(append(boids, evil), 3)
	if a.serial() != 2 {
		t.Fatalf("boid-a adopted a forged policy: %d", a.serial())
	}
	if a.currentView(t).Has(evil.cfg.Key.ID()) {
		t.Fatal("a boid on an unverifiable policy is in the view")
	}

	var bundle flockpolicy.Bundle
	if err := call(context.Background(), a.srv.Client(), http.MethodGet, a.srv.URL+"/fed/v1/policy?after=1", nil, &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Chain) != 1 {
		t.Fatalf("bundle after 1 has %d policies, want only the newest", len(bundle.Chain))
	}
}

func TestEmergencyPauseSpreads(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	boids := []*testBoid{a, b}
	rounds(boids, 2)

	raw, _ := json.Marshal(flockpolicy.PauseBody{Serial: 1, Issued: clk.now(), Expires: clk.now().Add(time.Hour)})
	d := flockpolicy.Document{Pause: raw}
	d.Sign(testRootKey)
	if _, _, err := flockpolicy.Adopt(context.Background(), a.store, testRoot, a.cfg.Key.ID(), flockpolicy.Bundle{Pause: &d}, clk.now()); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second)
	rounds(boids, 3)
	if res := leaseReason(t, a, b, homeUnit(t, b)); res.Granted || !strings.Contains(res.Reason, "emergency pause") {
		t.Fatalf("lease during an emergency pause: %+v", res)
	}
	clk.advance(time.Hour)
	if res := leaseReason(t, a, b, homeUnit(t, b)); !res.Granted {
		t.Fatalf("lease after the pause ended: %+v", res)
	}
}

func TestRevocation(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)

	ip := "172.30.0.5"
	fromC := signedObservation(c.cfg.Key, ip, 22, clk.now())
	fromA := signedObservation(a.cfg.Key, ip, 80, clk.now())
	a.data.AddRemoteObservations(context.Background(), []client.Observation{fromC, fromA})
	c.data.AddRemoteObservations(context.Background(), []client.Observation{fromC})

	cID := c.cfg.Key.ID()
	a.install(t, testPolicy(t, 2, clk.now(), func(b *flockpolicy.Body) {
		b.RevokedNodes = []flockpolicy.Revoked{{ID: cID, Reason: "test"}}
	}))
	clk.advance(time.Second)
	rounds(boids, 3)

	for _, x := range []*testBoid{a, b} {
		if s := peerStates(x)["boid-c"]; s != StateRevoked {
			t.Errorf("boid-c is %q on %s, want revoked", s, x.cfg.Name)
		}
		if x.currentView(t).Has(cID) {
			t.Errorf("boid-c is still in %s's view", x.cfg.Name)
		}
	}
	h, _ := a.data.Host(context.Background(), netip.MustParseAddr(ip))
	if len(h.Services) != 1 || h.Services[0].NodeID != a.cfg.Key.ID() {
		t.Fatalf("boid-a still holds boid-c's results: %+v", h.Services)
	}
	if c.serial() != 2 || !c.data.has(ip) {
		t.Fatal("the revoked boid must learn the policy and keep its own results")
	}
	if res := push(t, a, pushMsg{Observations: []client.Observation{fromC}}); res.Stored != 0 {
		t.Fatalf("push of a revoked boid's result: %+v", res)
	}
	if res := leaseReason(t, c, a, homeUnit(t, a)); res.Granted {
		t.Fatal("a revoked boid got a lease")
	}
	if found, _ := newTestSweeper(c, clk, func(*testBoid, catalog.Unit) { t.Error("a revoked boid scanned") }).Step(context.Background()); found {
		t.Fatal("a revoked boid swept")
	}

	// Lifting the revocation lets the boid be verified again.
	a.install(t, testPolicy(t, 3, clk.now(), nil))
	clk.advance(time.Second)
	rounds(boids, 3)
	if !a.currentView(t).Has(cID) {
		t.Fatalf("boid-c did not return after the revocation was lifted: %v", peerStates(a))
	}
}

func TestExpiredPolicy(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	rounds([]*testBoid{a, b}, 2)
	clk.advance(flockpolicy.DefaultLifetime)
	rounds([]*testBoid{a, b}, 1)
	if res := leaseReason(t, a, b, homeUnit(t, b)); res.Granted || !strings.Contains(res.Reason, "expired") {
		t.Fatalf("lease under an expired policy: %+v", res)
	}
	var st PolicyStatus
	if err := call(context.Background(), a.srv.Client(), http.MethodGet, a.srv.URL+"/fed/v1/policy/status", nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Serial != 1 || !strings.Contains(st.Halt, "expired") {
		t.Fatalf("status = %+v", st)
	}
	if !bytes.Contains([]byte(st.Root), []byte(testRoot.ID()[:8])) {
		t.Fatalf("status root = %q", st.Root)
	}
}

package fed

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

func TestFirstHomes(t *testing.T) {
	var peers []Peer
	for i := range 10 {
		peers = append(peers, Peer{Record: Record{ID: fmt.Sprintf("node-%d", i)}})
	}
	v := NewView(Member{ID: "self"}, peers, catalog.Default(), func(Peer) bool { return true })
	blocks := catalog.Default().Blocks(nil)[:2000]
	first := firstHomes(v, blocks)
	for _, b := range blocks {
		if want := v.Homes(b)[0].ID; first[b] != want {
			t.Fatalf("first home of %s is %s, want %s", b, first[b], want)
		}
	}
}

func refreshAll(boids []*testBoid) {
	for range 2 {
		for _, b := range boids {
			b.RefreshProgress(context.Background())
		}
	}
}

// TestFlockProgress has every boid arrive at the same count while the flock sweeps.
func TestFlockProgress(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)
	ctx := context.Background()

	ip := "172.30.0.9"
	a.data.AddRemoteObservations(ctx, []client.Observation{signedObservation(a.cfg.Key, ip, 22, clk.now()), signedObservation(a.cfg.Key, ip, 80, clk.now())})
	scanned := map[catalog.Unit]bool{}
	var sweepers []*Sweeper
	for _, x := range boids {
		sweepers = append(sweepers, newTestSweeper(x, clk, func(_ *testBoid, u catalog.Unit) { scanned[u] = true }))
	}
	for range 3 {
		for _, s := range sweepers {
			if _, err := s.Step(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, x := range boids {
		x.Replicate(ctx)
	}
	refreshAll(boids)
	if len(scanned) == 0 {
		t.Fatal("nothing was scanned")
	}

	units := len(labCatalog.Blocks(nil)) * len(labCatalog.Groups)
	for _, x := range boids {
		p, err := x.FlockProgress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if p.Units.Total != units || p.Units.ScannedEver != len(scanned) || p.Units.Fresh != len(scanned) || p.Rate.UnitsLast24h != len(scanned) {
			t.Errorf("%s counts %+v, want %d of %d units", x.cfg.Name, p.Units, len(scanned), units)
		}
		if p.Boids.Reporting != 3 || p.Boids.Known != 3 {
			t.Errorf("%s: %+v boids", x.cfg.Name, p.Boids)
		}
		if p.Hosts != 1 || p.OpenPorts != 2 {
			t.Errorf("%s: %d hosts, %d open ports, want 1 and 2", x.cfg.Name, p.Hosts, p.OpenPorts)
		}
		if p.Rate.ETAFullSweep == "" || len(p.Groups) != 2 || p.Groups[0].Name != "core ports" {
			t.Errorf("%s: %+v", x.cfg.Name, p)
		}
	}

	clk.advance(2 * time.Hour)
	refreshAll(boids)
	p, _ := b.FlockProgress(ctx)
	if p.Units.ScannedEver != len(scanned) || p.Units.Fresh != 0 {
		t.Fatalf("after min_rescan: %+v", p.Units)
	}
}

func TestProgressIsCapped(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	rounds([]*testBoid{a, b}, 2)
	ctx := context.Background()

	inflated := Progress{NodeID: b.cfg.Key.ID(), Catalog: b.catalogHash, Time: clk.now(), Groups: []GroupProgress{{Ever: 1000, Fresh: 2000}, {}}, Hosts: 1 << 40}
	sp, _ := signProgress(b.cfg.Key, inflated)
	a.data.SaveProgress(ctx, inflated.NodeID, inflated.Time, sp)

	other, _ := identity.Generate()
	sp, _ = signProgress(other, inflated)
	if _, err := sp.Open(); err == nil {
		t.Fatal("a count signed by another key opens")
	}
	a.data.SaveProgress(ctx, "forged", inflated.Time, sp)
	sp, _ = signProgress(other, Progress{NodeID: other.ID(), Catalog: a.catalogHash, Time: clk.now(), Groups: []GroupProgress{{Ever: 5}, {}}})
	a.data.SaveProgress(ctx, other.ID(), clk.now(), sp)

	p, err := a.FlockProgress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := a.view(ctx)
	held := 0
	for _, id := range firstHomes(f.View, labCatalog.Blocks(nil)) {
		if id == b.cfg.Key.ID() {
			held++
		}
	}
	if p.Boids.Reporting != 1 || p.Units.ScannedEver != held || p.Units.Fresh != held || p.Hosts != int64(held)*4 {
		t.Fatalf("got %+v, %d hosts; want boid-b capped at its %d blocks and the others ignored", p.Units, p.Hosts, held)
	}
}

package catalog

import (
	"net/netip"
	"testing"

	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/netset"
)

func TestDefaultGroups(t *testing.T) {
	c := Default()
	seen := map[uint16]int{}
	for _, g := range c.Groups {
		if len(g) == 0 || len(g) > groupSize {
			t.Fatalf("group of %d ports", len(g))
		}
		for _, p := range g {
			seen[p]++
		}
	}
	for _, p := range grab.DefaultPorts() {
		if seen[p] != 1 {
			t.Errorf("port %d is in %d groups", p, seen[p])
		}
	}
	for _, s := range grab.KnownServices("") {
		if !contains(c.Groups[0], s.Port) {
			t.Errorf("port %d has its own module but is not in group 0", s.Port)
		}
	}
}

func contains(ports []uint16, p uint16) bool {
	for _, q := range ports {
		if q == p {
			return true
		}
	}
	return false
}

func TestHash(t *testing.T) {
	a, b := Default(), Default()
	if a.Hash() != b.Hash() {
		t.Fatal("hash is not stable")
	}
	b.Replicas = 4
	if a.Hash() == b.Hash() {
		t.Fatal("hash ignores replicas")
	}
	lab, _ := Lab(netip.MustParsePrefix("172.30.0.0/26"))
	other, _ := Lab(netip.MustParsePrefix("172.30.0.64/26"))
	if lab.Hash() == other.Hash() {
		t.Fatal("hash ignores the universe")
	}
}

func TestBlocks(t *testing.T) {
	lab, err := Lab(netip.MustParsePrefix("172.30.0.0/26"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := lab.Blocks(nil)
	if len(blocks) != 16 || blocks[0].String() != "172.30.0.0/30" || blocks[15].String() != "172.30.0.60/30" {
		t.Fatalf("blocks = %v", blocks)
	}
	if got := lab.Block(netip.MustParseAddr("172.30.0.11")); got.String() != "172.30.0.8/30" {
		t.Fatalf("Block = %s", got)
	}
	skip := &netset.Set{}
	skip.Add(netip.MustParsePrefix("172.30.0.0/28"))
	skip.Add(netip.MustParsePrefix("172.30.0.17/32"))
	if got := len(lab.Blocks(skip)); got != 12 {
		t.Fatalf("%d blocks left, want 12: only whole blocks are skipped", got)
	}

	world := Default().Blocks(netset.Reserved(false))
	if len(world) < 50000 || len(world) > 60000 {
		t.Fatalf("%d /16 blocks outside reserved ranges", len(world))
	}
	if _, err := Lab(netip.MustParsePrefix("172.30.0.0/31")); err == nil {
		t.Fatal("a lab range smaller than a block must be rejected")
	}
}

func TestValid(t *testing.T) {
	lab, _ := Lab(netip.MustParsePrefix("172.30.0.0/26"))
	for u, want := range map[Unit]bool{
		{netip.MustParsePrefix("172.30.0.8/30"), 1}:  true,
		{netip.MustParsePrefix("172.30.0.8/30"), 2}:  false,
		{netip.MustParsePrefix("172.30.0.8/29"), 0}:  false,
		{netip.MustParsePrefix("172.30.0.9/30"), 0}:  false,
		{netip.MustParsePrefix("172.30.0.64/30"), 0}: false,
	} {
		if got := lab.Valid(u); got != want {
			t.Errorf("Valid(%v) = %v", u, got)
		}
	}
}

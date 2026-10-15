package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

func TestOptOuts(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	other, _ := identity.Generate()
	ip := netip.MustParseAddr("192.0.2.7")
	now := time.Now().UTC().Truncate(time.Microsecond)
	run, _ := st.StartRun(ctx, testKey.ID(), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, []uint16{22}, nil)
	if err := st.AddObservation(ctx, run, testKey, obs(ip.String(), 22, "ssh22", "ssh", `{}`)); err != nil {
		t.Fatal(err)
	}

	add := fed.SignOptOut(other, ip, fed.OptOutAdd, now)
	stored, capped, err := st.AddOptOuts(ctx, []fed.OptOut{add, add})
	if err != nil || stored != 1 || capped != 0 {
		t.Fatalf("AddOptOuts = %d, %d, %v; want the duplicate skipped", stored, capped, err)
	}
	if h, _ := st.Host(ctx, ip); len(h.Services) != 0 {
		t.Fatal("stored results of an opted-out address were kept")
	}
	if err := st.AddObservation(ctx, run, testKey, obs(ip.String(), 22, "ssh22", "ssh", `{}`)); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.AddRemoteObservations(ctx, []client.Observation{remoteObs(other, ip.String(), now)}); n != 0 {
		t.Fatal("a pushed result for an opted-out address was stored")
	}
	if h, _ := st.Host(ctx, ip); len(h.Services) != 0 {
		t.Fatal("a result for an opted-out address was stored")
	}
	if ex, _ := st.Excluded(ctx, ip); !ex {
		t.Fatal("Excluded misses an opted-out address")
	}
	if set, _ := st.ExclusionSet(ctx, []netip.Prefix{netip.MustParsePrefix("192.0.0.0/16")}); !set.Contains(ip) || set.Contains(netip.MustParseAddr("192.0.2.8")) {
		t.Fatal("ExclusionSet must hold exactly the opted-out address")
	}
	if set, _ := st.ExclusionSet(ctx, []netip.Prefix{netip.MustParsePrefix("198.51.0.0/16")}); set.Len() != 0 {
		t.Fatal("ExclusionSet holds an opt-out outside the scanned range")
	}
	if set, _ := st.RangeExclusions(ctx); set.Len() != 0 {
		t.Fatal("RangeExclusions holds an opted-out address")
	}
	active, err := st.ActiveOptOuts(ctx)
	if err != nil || len(active) != 1 || active[0].IP != ip || !active[0].Verify() {
		t.Fatalf("ActiveOptOuts = %+v, %v", active, err)
	}
	if n, _ := st.OptOutRequests(ctx, other.ID(), ip, now.Add(-time.Hour)); n != 1 {
		t.Fatalf("OptOutRequests = %d, want 1", n)
	}

	remove := fed.SignOptOut(testKey, ip, fed.OptOutRemove, now.Add(time.Second))
	if _, _, err := st.AddOptOuts(ctx, []fed.OptOut{remove}); err != nil {
		t.Fatal(err)
	}
	if ex, _ := st.Excluded(ctx, ip); ex {
		t.Fatal("a withdrawn opt-out still applies")
	}
	latest, ok, err := st.LatestOptOut(ctx, ip)
	if err != nil || !ok || latest.Action != fed.OptOutRemove {
		t.Fatalf("LatestOptOut = %+v, %v, %v", latest, ok, err)
	}
	log, err := st.OptOutsAfter(ctx, 0, 10)
	if err != nil || len(log) != 2 || log[0].ID >= log[1].ID {
		t.Fatalf("OptOutsAfter = %+v, %v", log, err)
	}

	// The withdrawal goes with its revoked signer, so the opt-out applies again.
	if err := st.SyncRevoked(ctx, []string{testKey.ID()}, other.ID()); err != nil {
		t.Fatal(err)
	}
	if ex, _ := st.Excluded(ctx, ip); !ex {
		t.Fatal("a revoked boid's withdrawal still counts")
	}
	if err := st.DropShunned(ctx, other.ID()); err != nil {
		t.Fatal(err)
	}
	if ex, _ := st.Excluded(ctx, ip); ex {
		t.Fatal("a shunned boid's opt-out still counts")
	}

	if err := st.SaveOptOutCursor(ctx, other.ID(), 42); err != nil {
		t.Fatal(err)
	}
	if after, err := st.OptOutCursor(ctx, other.ID()); err != nil || after != 42 {
		t.Fatalf("OptOutCursor = %d, %v", after, err)
	}
}

func TestOptOutCap(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	day := time.Now().UTC().Truncate(24 * time.Hour)
	var list []fed.OptOut
	for i := range fed.MaxOptOutsPerDay + 1 {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		list = append(list, fed.SignOptOut(testKey, ip, fed.OptOutAdd, day.Add(time.Duration(i)*time.Second)))
	}
	stored, capped, err := st.AddOptOuts(ctx, list)
	if err != nil || stored != fed.MaxOptOutsPerDay || capped != 1 {
		t.Fatalf("AddOptOuts = %d, %d, %v; want %d stored, 1 capped", stored, capped, err, fed.MaxOptOutsPerDay)
	}
	next := fed.SignOptOut(testKey, netip.MustParseAddr("198.18.200.1"), fed.OptOutAdd, day.Add(24*time.Hour))
	if stored, _, _ := st.AddOptOuts(ctx, []fed.OptOut{next}); stored != 1 {
		t.Fatal("the cap still applies on the next UTC day")
	}
	expired := fed.SignOptOut(testKey, netip.MustParseAddr("198.18.201.1"), fed.OptOutAdd, time.Now().Add(-fed.MaxOptOutAge-time.Hour))
	st.AddOptOuts(ctx, []fed.OptOut{expired})
	if ex, _ := st.Excluded(ctx, expired.IP); ex {
		t.Fatal("an expired opt-out still applies")
	}
}

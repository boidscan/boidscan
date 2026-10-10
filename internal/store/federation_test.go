package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

func remoteObs(k fed.Signer, ip string, at time.Time) client.Observation {
	o := client.Observation{NodeID: k.ID(), IP: ip, Port: 443, Name: "https443", Protocol: "http", Status: "success",
		SeenAt: at.UTC().Truncate(time.Microsecond), Data: json.RawMessage(tlsRaw)}
	o.Signature = k.Sign(sig.ObservationMessage(o.IP, o.Port, o.Name, o.Protocol, o.Status, o.SeenAt, o.Data))
	return o
}

func TestRemoteObservations(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	other, _ := identity.Generate()
	now := time.Now()
	st.AddExclusion(ctx, netip.MustParsePrefix("192.0.2.128/25"), "")

	a := remoteObs(other, "192.0.2.1", now)
	n, err := st.AddRemoteObservations(ctx, []client.Observation{a, a, remoteObs(other, "192.0.2.200", now)})
	if err != nil || n != 1 {
		t.Fatalf("stored %d, %v; want the duplicate and the excluded address skipped", n, err)
	}
	h, err := st.Host(ctx, netip.MustParseAddr("192.0.2.1"))
	if err != nil || len(h.Services) != 1 {
		t.Fatalf("Host = %+v, %v", h, err)
	}
	if err := h.Services[0].Verify(); err != nil || h.Services[0].NodeID != other.ID() || h.Services[0].CertSHA256 != "aa11" {
		t.Fatalf("a pushed observation must keep its scanner and signature: %+v, %v", h.Services[0], err)
	}

	list, err := st.ObservationsAfter(ctx, 0, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("ObservationsAfter = %d, %v", len(list), err)
	}
	if more, _ := st.ObservationsAfter(ctx, list[0].ID, 10); len(more) != 0 {
		t.Fatalf("rows after the last one: %d", len(more))
	}
	if ex, _ := st.Excluded(ctx, netip.MustParseAddr("192.0.2.200")); !ex {
		t.Fatal("Excluded misses an excluded address")
	}
}

func TestLeasesAndCoverage(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	other, _ := identity.Generate()
	u := catalog.Unit{Block: netip.MustParsePrefix("192.0.2.0/24"), Group: 2}

	acquire := func(holder string, ttl time.Duration) bool {
		t.Helper()
		ok, err := st.AcquireLease(ctx, u, holder, ttl, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !acquire(testKey.ID(), time.Minute) {
		t.Fatal("free unit not leased")
	}
	if acquire(other.ID(), time.Minute) {
		t.Fatal("leased unit granted to another holder")
	}
	if !acquire(testKey.ID(), time.Minute) {
		t.Fatal("holder could not renew")
	}
	if err := st.ReleaseLease(ctx, u, other.ID()); err != nil {
		t.Fatal(err)
	}
	if acquire(other.ID(), time.Minute) {
		t.Fatal("another holder released a lease it does not hold")
	}
	st.ReleaseLease(ctx, u, testKey.ID())
	if !acquire(other.ID(), -time.Second) || !acquire(testKey.ID(), time.Minute) {
		t.Fatal("an expired lease must not block the unit")
	}

	status, err := st.UnitStatus(ctx)
	if err != nil || len(status) != 1 || status[0].LeasedBy != testKey.ID() || !status[0].ScannedAt.IsZero() {
		t.Fatalf("UnitStatus = %+v, %v", status, err)
	}

	cov := fed.SignCoverage(testKey, u, "hash", time.Now())
	if n, err := st.AddCoverage(ctx, []fed.Coverage{cov, cov}); err != nil || n != 1 {
		t.Fatalf("AddCoverage = %d, %v", n, err)
	}
	status, _ = st.UnitStatus(ctx)
	if len(status) != 1 || status[0].LeasedBy != "" || status[0].ScannedBy != testKey.ID() {
		t.Fatalf("coverage must end the scanner's lease: %+v", status)
	}
	if acquire(other.ID(), time.Minute) {
		t.Fatal("a unit scanned within min-rescan was leased")
	}
	got, err := st.CoverageAfter(ctx, 0, 10)
	if err != nil || len(got) != 1 || !got[0].Verify() || got[0].Unit() != u {
		t.Fatalf("CoverageAfter = %+v, %v", got, err)
	}
}

func TestReplicaState(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if r, err := st.ReplicaState(ctx, "home"); err != nil || r.View != nil || r.Obs != 0 {
		t.Fatalf("unknown home = %+v, %v", r, err)
	}
	want := fed.ReplicaState{View: []string{"a", "b"}, Obs: 7, Cov: 3, CatchUp: true, Old: []string{"a", "c"}, OldObs: 5, OldCov: 2}
	if err := st.SaveReplicaState(ctx, "home", want); err != nil {
		t.Fatal(err)
	}
	want.Obs = 9
	st.SaveReplicaState(ctx, "home", want)
	got, err := st.ReplicaState(ctx, "home")
	if err != nil || !slices.Equal(got.View, want.View) || !slices.Equal(got.Old, want.Old) || got.Obs != 9 || got.Cov != 3 || !got.CatchUp || got.OldObs != 5 || got.OldCov != 2 {
		t.Fatalf("ReplicaState = %+v, %v", got, err)
	}
}

func TestSweepRuns(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	u := catalog.Unit{Block: netip.MustParsePrefix("198.51.100.0/24"), Group: 1}
	st.StartRun(ctx, testKey.ID(), []netip.Prefix{u.Block}, []uint16{80}, nil)
	if recent, _ := st.RecentRun(ctx, u, time.Hour); recent {
		t.Fatal("a manual scan counts as a sweep run")
	}
	id, err := st.StartRun(ctx, testKey.ID(), []netip.Prefix{u.Block}, []uint16{80}, &u)
	if err != nil {
		t.Fatal(err)
	}
	if recent, _ := st.RecentRun(ctx, u, time.Hour); recent {
		t.Fatal("an unfinished run counts")
	}
	st.FinishRun(ctx, id, nil)
	if recent, _ := st.RecentRun(ctx, u, time.Hour); !recent {
		t.Fatal("a finished run does not count")
	}
	runs, err := st.SweepRuns(ctx, 10)
	if err != nil || len(runs) != 1 || runs[0].Unit != u || runs[0].FinishedAt.IsZero() {
		t.Fatalf("SweepRuns = %+v, %v", runs, err)
	}
}

package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

func signedPolicy(t *testing.T, k *identity.Key, serial uint64, revoked ...string) flockpolicy.Policy {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	b := flockpolicy.Body{
		Serial: serial, Issued: now, Expires: now.Add(time.Hour), MaxRatePPS: 100,
		MinRescan: flockpolicy.Duration(time.Hour), Catalog: strings.Repeat("ab", 32),
		Maintainers: flockpolicy.Maintainers{Keys: []string{k.ID()}, Threshold: 1},
	}
	for _, id := range revoked {
		b.RevokedNodes = append(b.RevokedNodes, flockpolicy.Revoked{ID: id})
	}
	raw, _ := json.MarshalIndent(b, "", "  ")
	d := flockpolicy.Document{Policy: raw}
	d.Sign(k)
	p, err := flockpolicy.Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicies(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	k, _ := identity.Generate()

	if s, err := st.PolicyState(ctx); err != nil || s.Latest != nil {
		t.Fatalf("empty store: %+v, %v", s, err)
	}
	for _, serial := range []uint64{1, 3} {
		if ok, err := st.AddPolicy(ctx, signedPolicy(t, k, serial)); !ok || err != nil {
			t.Fatalf("AddPolicy(%d) = %v, %v", serial, ok, err)
		}
	}
	for _, serial := range []uint64{2, 3} {
		if ok, _ := st.AddPolicy(ctx, signedPolicy(t, k, serial)); ok {
			t.Fatalf("policy %d stored after 3", serial)
		}
	}
	raw, _ := json.Marshal(flockpolicy.PauseBody{Serial: 3, Issued: time.Now(), Expires: time.Now().Add(time.Hour)})
	pd := flockpolicy.Document{Pause: raw}
	pd.Sign(k)
	pause, err := flockpolicy.ParsePause(pd)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.AddPause(ctx, pause); !ok || err != nil {
		t.Fatalf("AddPause = %v, %v", ok, err)
	}
	if ok, _ := st.AddPause(ctx, pause); ok {
		t.Fatal("a second pause for the same policy was stored")
	}

	s, err := st.PolicyState(ctx)
	if err != nil || s.Serial() != 3 || len(s.Expires) != 2 || !s.Paused(time.Now()) {
		t.Fatalf("PolicyState = %+v, %v", s, err)
	}
	if got := s.Latest.Doc.SignedBy(s.Latest.Maintainers); len(got) != 1 {
		t.Fatal("a stored policy lost its signature")
	}
	all, err := st.Policies(ctx)
	if err != nil || len(all) != 2 || all[0].Serial != 1 {
		t.Fatalf("Policies = %d, %v", len(all), err)
	}
}

func TestSyncRevoked(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	bad, _ := identity.Generate()
	now := time.Now()

	rec := fed.Record{ID: bad.ID(), Name: "bad", Endpoint: "http://192.0.2.5", Time: now, Signature: []byte("s")}
	st.SavePeer(ctx, rec)
	st.MarkVerified(ctx, rec.ID, rec.Endpoint)
	st.SetPeerState(ctx, rec.ID, fed.StateAlive)
	st.AddRemoteObservations(ctx, []client.Observation{remoteObs(bad, "192.0.2.1", now), remoteObs(testKey, "192.0.2.1", now)})
	u := catalog.Unit{Block: netip.MustParsePrefix("192.0.2.0/30")}
	st.AddCoverage(ctx, []fed.Coverage{fed.SignCoverage(bad, u, "c", now)})
	st.AcquireLease(ctx, catalog.Unit{Block: netip.MustParsePrefix("192.0.2.4/30")}, bad.ID(), time.Minute, time.Hour)

	if err := st.SyncRevoked(ctx, []string{bad.ID(), testKey.ID()}, testKey.ID()); err != nil {
		t.Fatal(err)
	}
	if p := onlyPeer(t, st); p.State != fed.StateRevoked {
		t.Fatalf("peer state %q, want revoked", p.State)
	}
	h, _ := st.Host(ctx, netip.MustParseAddr("192.0.2.1"))
	if len(h.Services) != 1 || h.Services[0].NodeID != testKey.ID() {
		t.Fatalf("Host = %+v; want only this boid's own result", h.Services)
	}
	if status, _ := st.UnitStatus(ctx, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/30"), netip.MustParsePrefix("192.0.2.4/30")}); len(status) != 0 {
		t.Fatalf("coverage or leases of a revoked boid remain: %+v", status)
	}

	if err := st.SyncRevoked(ctx, nil, testKey.ID()); err != nil {
		t.Fatal(err)
	}
	if p := onlyPeer(t, st); p.State != fed.StateNew || p.Verified {
		t.Fatalf("after the revocation is lifted: %+v", p)
	}
}

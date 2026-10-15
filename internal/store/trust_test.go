package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/fed"
	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

func TestSamplesAndScore(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	scanner, _ := identity.Generate()
	now := time.Now()
	confirmed := remoteObs(scanner, "192.0.2.1", now)
	unchecked := remoteObs(scanner, "192.0.2.2", now)
	st.AddRemoteObservations(ctx, []client.Observation{confirmed, unchecked})
	u := catalog.Unit{Block: netip.MustParsePrefix("192.0.2.0/30")}
	st.AddCoverage(ctx, []fed.Coverage{fed.SignCoverage(testKey, u, "c", now.Add(-time.Hour)), fed.SignCoverage(scanner, u, "c", now)})

	tgt := fed.CheckTarget{IP: netip.MustParseAddr("192.0.2.1"), Port: 443, Name: "https443"}
	sm := fed.Sample{Key: "k1", Subject: confirmed.Signature, Kind: fed.KindObservation, Scanner: scanner.ID(), Target: tgt,
		ReportedOpen: true, ReportedFP: "aa11", ScannedAt: confirmed.SeenAt, Evidence: confirmed}
	for range 2 {
		if err := st.AddSample(ctx, sm); err != nil {
			t.Fatal(err)
		}
	}
	open, err := st.OpenSamples(ctx, 10)
	if err != nil || len(open) != 1 {
		t.Fatalf("OpenSamples = %d, %v; want the duplicate subject skipped", len(open), err)
	}
	if got := open[0]; got.Target != tgt || got.Evidence.Verify() != nil || got.Checkers != nil {
		t.Fatalf("sample did not survive the round trip: %+v", got)
	}
	id := open[0].ID
	st.SetCheckers(ctx, id, []string{"a", "b"})
	st.SaveVote(ctx, id, fed.Vote{Checker: "a", CheckResult: fed.CheckResult{Open: true, Fingerprint: "aa11"}})
	st.SaveVote(ctx, id, fed.Vote{Checker: "a", CheckResult: fed.CheckResult{Open: false}})
	if votes, _ := st.Votes(ctx, id); len(votes) != 1 || !votes[0].Open {
		t.Fatalf("Votes = %+v; a checker votes once", votes)
	}
	st.Decide(ctx, id, fed.VerdictPass)
	if open, _ := st.OpenSamples(ctx, 10); len(open) != 0 {
		t.Fatal("a decided sample is still open")
	}
	cov := sm
	cov.Key, cov.Subject, cov.Kind = "k2", []byte("coverage-signature"), fed.KindCoverage
	st.AddSample(ctx, cov)
	open, _ = st.OpenSamples(ctx, 10)
	st.Decide(ctx, open[0].ID, fed.VerdictMissed)
	if sc, err := st.Score(ctx, scanner.ID(), 10); err != nil || sc.Pass != 1 || sc.Missed != 1 || sc.CoverageDecided != 1 {
		t.Fatalf("Score = %+v, %v", sc, err)
	}

	if err := st.DropShunned(ctx, scanner.ID()); err != nil {
		t.Fatal(err)
	}
	if h, _ := st.Host(ctx, netip.MustParseAddr("192.0.2.1")); len(h.Services) != 1 {
		t.Fatal("a result confirmed by a sample was dropped")
	}
	if h, _ := st.Host(ctx, netip.MustParseAddr("192.0.2.2")); len(h.Services) != 0 {
		t.Fatal("an unchecked result of a shunned boid survived")
	}
	if status, _ := st.UnitStatus(ctx, []netip.Prefix{u.Block}); len(status) != 1 || status[0].ScannedBy != testKey.ID() {
		t.Fatalf("after dropping a shunned boid's coverage, status = %+v; want the older coverage of another boid", status)
	}
}

func TestEvidenceAndReported(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	other, scanner := testKey, func() *identity.Key { k, _ := identity.Generate(); return k }()
	now := time.Now()
	earlier := remoteObs(other, "192.0.2.1", now.Add(-time.Hour))
	st.AddRemoteObservations(ctx, []client.Observation{earlier, remoteObs(scanner, "192.0.2.2", now.Add(-time.Hour))})
	u := catalog.Unit{Block: netip.MustParsePrefix("192.0.2.0/30")}

	ev, err := st.CoverageEvidence(ctx, u, []uint16{443}, scanner.ID(), now.Add(-24*time.Hour), now, 10)
	if err != nil || len(ev) != 1 || ev[0].IP != "192.0.2.1" {
		t.Fatalf("CoverageEvidence = %+v, %v; want only the other boid's result", ev, err)
	}
	if ev, _ := st.CoverageEvidence(ctx, u, []uint16{22}, scanner.ID(), now.Add(-24*time.Hour), now, 10); len(ev) != 0 {
		t.Fatal("evidence on a port outside the group")
	}
	tgt := fed.CheckTarget{IP: netip.MustParseAddr("192.0.2.2"), Port: 443, Name: "https443"}
	if ok, _ := st.Reported(ctx, scanner.ID(), tgt, now.Add(-2*time.Hour)); !ok {
		t.Fatal("Reported misses the scanner's result")
	}
	if ok, _ := st.Reported(ctx, scanner.ID(), tgt, now); ok {
		t.Fatal("Reported counts a result from before the scan")
	}
}

func TestChecks(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	o := remoteObs(testKey, "192.0.2.1", time.Now())
	tgt := fed.CheckTarget{IP: netip.MustParseAddr("192.0.2.1"), Port: 443, Name: "https443"}
	c := fed.Check{Requester: "r", Key: "k", Kind: fed.KindObservation, Scanner: testKey.ID(), Target: tgt, Evidence: o}
	st.AddCheck(ctx, c)
	st.AddCheck(ctx, c)
	pending, err := st.PendingChecks(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Target != tgt || pending[0].Evidence.Verify() != nil {
		t.Fatalf("PendingChecks = %+v, %v", pending, err)
	}
	if _, ok, _ := st.RecentCheck(ctx, tgt, time.Now().Add(-time.Hour)); ok {
		t.Fatal("an unfinished check counts as recent")
	}
	st.FinishCheck(ctx, pending[0].ID, fed.CheckResult{Open: true, Fingerprint: "aa11"})
	got, ok, err := st.CheckByKey(ctx, "r", "k")
	if err != nil || !ok || !got.Done || got.Result.Fingerprint != "aa11" {
		t.Fatalf("CheckByKey = %+v, %v, %v", got, ok, err)
	}
	if r, ok, _ := st.RecentCheck(ctx, tgt, time.Now().Add(-time.Hour)); !ok || !r.Open {
		t.Fatalf("RecentCheck = %+v, %v", r, ok)
	}
	done := fed.Check{Requester: "r", Key: "k2", Target: tgt, Evidence: o, Done: true, Result: fed.CheckResult{Unavailable: true}}
	st.AddCheck(ctx, done)
	if got, _, _ := st.CheckByKey(ctx, "r", "k2"); !got.Done || !got.Result.Unavailable {
		t.Fatalf("a check stored as done: %+v", got)
	}
	if _, ok, _ := st.CheckByKey(ctx, "other", "k"); ok {
		t.Fatal("a check is visible to another requester")
	}
}

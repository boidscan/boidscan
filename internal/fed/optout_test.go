package fed

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/identity"
	"github.com/boidscan/boidscan/pkg/client"
)

// latestOptOut is the newest attestation for ip; the caller holds m.mu.
func (m *memData) latestOptOut(ip netip.Addr) (OptOut, bool) {
	var best OptOut
	found := false
	for _, o := range m.optOuts {
		if o.IP != ip {
			continue
		}
		if !found || o.Time.After(best.Time) || (o.Time.Equal(best.Time) && bytes.Compare(o.Signature, best.Signature) > 0) {
			best, found = o, true
		}
	}
	return best, found
}

func (m *memData) optedOut(ip netip.Addr) bool {
	o, ok := m.latestOptOut(ip.Unmap())
	return ok && o.Active(m.now())
}

func (m *memData) activeOptOuts() []OptOut {
	var out []OptOut
	for _, o := range m.optOuts {
		if latest, _ := m.latestOptOut(o.IP); bytes.Equal(latest.Signature, o.Signature) && o.Active(m.now()) {
			out = append(out, o)
		}
	}
	return out
}

func (m *memData) AddOptOuts(_ context.Context, list []OptOut) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var stored, capped int
	for _, o := range list {
		if slices.ContainsFunc(m.optOuts, func(x OptOut) bool { return bytes.Equal(x.Signature, o.Signature) }) {
			continue
		}
		day := o.Time.UTC().Truncate(24 * time.Hour)
		n := 0
		for _, x := range m.optOuts {
			if x.Signer == o.Signer && x.Time.UTC().Truncate(24*time.Hour).Equal(day) {
				n++
			}
		}
		if n >= MaxOptOutsPerDay {
			capped++
			continue
		}
		m.optOutID++
		o.ID = m.optOutID
		m.optOuts = append(m.optOuts, o)
		stored++
		if m.optedOut(o.IP) {
			m.obs = slices.DeleteFunc(m.obs, func(x client.Observation) bool { return x.IP == o.IP.String() })
		}
	}
	return stored, capped, nil
}

func (m *memData) OptOutsBy(_ context.Context, signer string, from time.Time, limit int) ([]OptOut, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.optOutReads++
	var out []OptOut
	for _, o := range m.optOuts {
		if o.Signer == signer && !o.Time.Before(from) {
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b OptOut) int { return cmp.Or(a.Time.Compare(b.Time), bytes.Compare(a.Signature, b.Signature)) })
	return out[:min(limit, len(out))], nil
}

func (m *memData) OptOutHeads(context.Context) ([]OptOutHead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]time.Time{}
	for _, o := range m.optOuts {
		if o.Time.After(latest[o.Signer]) {
			latest[o.Signer] = o.Time
		}
	}
	var out []OptOutHead
	for s, t := range latest {
		out = append(out, OptOutHead{Signer: s, Latest: t})
	}
	return out, nil
}

func (m *memData) ActiveOptOuts(_ context.Context, after netip.Addr, limit int) ([]OptOut, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OptOut
	for _, o := range m.activeOptOuts() {
		if !after.IsValid() || o.IP.Compare(after) > 0 {
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b OptOut) int { return a.IP.Compare(b.IP) })
	return out[:min(limit, len(out))], nil
}

func (m *memData) LatestOptOut(_ context.Context, ip netip.Addr) (OptOut, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.latestOptOut(ip)
	return o, ok, nil
}

func (m *memData) OptOutRequests(_ context.Context, signer string, ip netip.Addr, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range m.optOuts {
		if o.Signer == signer && o.IP == ip && o.Time.After(since) {
			n++
		}
	}
	return n, nil
}

func (m *memData) OptOutCursor(_ context.Context, signer string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[signer], nil
}

func (m *memData) SaveOptOutCursor(_ context.Context, signer string, after time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursors[signer] = after
	return nil
}

func newTestDesk(k Signer, d *memData, clk *clock) *OptOutDesk {
	desk := NewOptOutDesk(k, d, true)
	desk.now = clk.now
	return desk
}

func TestOptOutDesk(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	key, _ := identity.Generate()
	d := newMemData(clk.now)
	desk := newTestDesk(key, d, clk)
	ctx := context.Background()
	ip := netip.MustParseAddr("172.30.0.5")
	result := signedObservation(key, ip.String(), 22, clk.now())
	d.AddRemoteObservations(ctx, []client.Observation{result})

	for _, bad := range []string{"127.0.0.1", "2001:db8::1", "203.0.113.9"} {
		if _, err := desk.Request(ctx, netip.MustParseAddr(bad), OptOutAdd); !errors.Is(err, ErrOptOutAddress) {
			t.Errorf("opt-out for %s: %v, want ErrOptOutAddress", bad, err)
		}
	}
	if _, err := NewOptOutDesk(key, d, false).Request(ctx, ip, OptOutAdd); !errors.Is(err, ErrOptOutAddress) {
		t.Errorf("a private address was accepted outside the lab: %v", err)
	}

	o, err := desk.Request(ctx, ip, OptOutAdd)
	if err != nil || !o.Expires.Equal(clk.now().Add(MaxOptOutAge)) || !o.Verify() {
		t.Fatalf("Request = %+v, %v", o, err)
	}
	if d.has(ip.String()) {
		t.Error("stored results for an opted-out address were kept")
	}
	if n, _ := d.AddRemoteObservations(ctx, []client.Observation{result}); n != 0 {
		t.Error("a pushed result for an opted-out address was stored")
	}
	if _, active, _ := desk.Status(ctx, ip); !active {
		t.Error("status does not show the opt-out")
	}
	if set, _ := d.ExclusionSet(ctx, []netip.Prefix{netip.PrefixFrom(ip, 16).Masked()}); !set.Contains(ip) {
		t.Error("the exclusion set misses the opt-out")
	}

	clk.advance(time.Second)
	if _, err := desk.Request(ctx, ip, OptOutRemove); err != nil {
		t.Fatal(err)
	}
	if _, active, _ := desk.Status(ctx, ip); active {
		t.Error("the opt-out is still active after its withdrawal")
	}
	if _, err := desk.Request(ctx, ip, OptOutRemove); !errors.Is(err, ErrNotOptedOut) {
		t.Errorf("second withdrawal: %v, want ErrNotOptedOut", err)
	}

	for range optOutsPerHour - 2 {
		clk.advance(time.Millisecond)
		if _, err := desk.Request(ctx, ip, OptOutAdd); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := desk.Request(ctx, ip, OptOutAdd); !errors.Is(err, ErrOptOutRate) {
		t.Fatalf("request %d within an hour: %v, want ErrOptOutRate", optOutsPerHour+1, err)
	}
	clk.advance(time.Hour)
	if _, err := desk.Request(ctx, ip, OptOutAdd); err != nil {
		t.Fatalf("renewing an hour later: %v", err)
	}
	clk.advance(MaxOptOutAge)
	if _, active, _ := desk.Status(ctx, ip); active {
		t.Error("the opt-out outlived its expiry")
	}
}

// TestOptOutsSpread: an opt-out taken by one boid reaches the others, also
// through a boid that only passed it on, and so does its withdrawal.
func TestOptOutsSpread(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)
	ctx := context.Background()
	ip := netip.MustParseAddr("172.30.0.9")
	for _, x := range boids {
		x.data.AddRemoteObservations(ctx, []client.Observation{signedObservation(x.cfg.Key, ip.String(), 22, clk.now())})
	}

	if _, err := newTestDesk(a.cfg.Key, a.data, clk).Request(ctx, ip, OptOutAdd); err != nil {
		t.Fatal(err)
	}
	b.SyncOptOuts(ctx)
	a.offline.Store(true)
	c.SyncOptOuts(ctx)
	for _, x := range boids[1:] {
		if ex, _ := x.data.Excluded(ctx, ip); !ex || x.data.has(ip.String()) {
			t.Errorf("%s: opted out %v, still holds results %v", x.cfg.Name, ex, x.data.has(ip.String()))
		}
	}
	var list []OptOut
	if err := call(ctx, c.client, http.MethodGet, c.srv.URL+"/fed/v1/optouts", nil, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].IP != ip || list[0].Signer != a.cfg.Key.ID() || !list[0].Verify() {
		t.Fatalf("/fed/v1/optouts on boid-c = %+v", list)
	}
	if err := call(ctx, c.client, http.MethodGet, c.srv.URL+"/fed/v1/optouts?after="+ip.String(), nil, &list); err != nil || len(list) != 0 {
		t.Fatalf("/fed/v1/optouts after the last address = %+v, %v", list, err)
	}

	a.offline.Store(false)
	clk.advance(time.Second)
	if _, err := newTestDesk(c.cfg.Key, c.data, clk).Request(ctx, ip, OptOutRemove); err != nil {
		t.Fatal(err)
	}
	b.SyncOptOuts(ctx)
	a.SyncOptOuts(ctx)
	for _, x := range boids {
		if ex, _ := x.data.Excluded(ctx, ip); ex {
			t.Errorf("%s still honours a withdrawn opt-out", x.cfg.Name)
		}
	}
}

func resign(k Signer, o OptOut) OptOut {
	o.Signer = k.ID()
	o.Signature = k.Sign(o.message())
	return o
}

func TestScreenOptOuts(t *testing.T) {
	signer, _ := identity.Generate()
	other, _ := identity.Generate()
	ip := netip.MustParseAddr("192.0.2.80")
	now := time.Now()

	good := SignOptOut(signer, ip, OptOutAdd, now)
	tooLong := good
	tooLong.Expires = now.Add(MaxOptOutAge + time.Hour)
	future := SignOptOut(signer, ip, OptOutAdd, now.Add(time.Hour))
	forged := good
	forged.IP = netip.MustParseAddr("192.0.2.81")
	expired := SignOptOut(signer, ip, OptOutAdd, now.Add(-MaxOptOutAge-time.Hour))
	page := []OptOut{good, resign(signer, tooLong), future, forged, expired, SignOptOut(other, ip, OptOutAdd, now)}
	accept, rejected := screenOptOuts(now, signer.ID(), page)
	if len(accept) != 1 || !bytes.Equal(accept[0].Signature, good.Signature) || rejected != 4 {
		t.Fatalf("screen = %d accepted, %d rejected; want 1, 4", len(accept), rejected)
	}
}

// TestOptOutsReadOnce: a boid reads each signer's attestations once, not
// again from every peer, and skips signers it does not accept until it does.
func TestOptOutsReadOnce(t *testing.T) {
	clk := &clock{t: time.Now()}
	a := newDataBoid(t, "boid-a", clk)
	b := newDataBoid(t, "boid-b", clk, a.srv.URL)
	c := newDataBoid(t, "boid-c", clk, a.srv.URL)
	boids := []*testBoid{a, b, c}
	rounds(boids, 2)
	ctx := context.Background()
	desk := newTestDesk(a.cfg.Key, a.data, clk)
	for i := range 3 {
		if _, err := desk.Request(ctx, netip.AddrFrom4([4]byte{172, 30, 1, byte(i)}), OptOutAdd); err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Second)
	}
	b.SyncOptOuts(ctx)
	f, err := c.view(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.pullOptOuts(ctx, f, f.peers[a.cfg.Key.ID()]); err != nil {
		t.Fatal(err)
	}
	if cur, _ := c.data.OptOutCursor(ctx, a.cfg.Key.ID()); !cur.Equal(clk.now().Add(-time.Second).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("cursor for boid-a = %v", cur)
	}
	if n := len(c.data.optOuts); n != 3 {
		t.Fatalf("boid-c holds %d opt-outs, want 3", n)
	}
	// boid-b holds the same attestations; reading it must not fetch them again.
	b.data.optOutReads = 0
	if err := c.pullOptOuts(ctx, f, f.peers[b.cfg.Key.ID()]); err != nil {
		t.Fatal(err)
	}
	if b.data.optOutReads != 0 {
		t.Fatalf("boid-c read boid-b's log %d times for attestations it already had", b.data.optOutReads)
	}

	c.data.SetTrust(ctx, a.cfg.Key.ID(), TrustShunned, false)
	c.data.DropShunned(ctx, a.cfg.Key.ID())
	if f, err = c.view(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.pullOptOuts(ctx, f, f.peers[b.cfg.Key.ID()]); err != nil {
		t.Fatal(err)
	}
	if n := len(c.data.activeOptOuts()); n != 0 {
		t.Fatalf("boid-c took %d opt-outs signed by a shunned boid", n)
	}
}

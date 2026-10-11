package flockpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/boidscan/boidscan/internal/identity"
)

var (
	now     = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	catHash = strings.Repeat("ab", 32)
)

func keys(t *testing.T, n int) []*identity.Key {
	t.Helper()
	var out []*identity.Key
	for range n {
		k, err := identity.Generate()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func set(threshold int, ks ...*identity.Key) Maintainers {
	m := Maintainers{Threshold: threshold}
	for _, k := range ks {
		m.Keys = append(m.Keys, k.ID())
	}
	return m
}

func body(serial uint64, m Maintainers) Body {
	return Body{
		Serial:       serial,
		Issued:       now,
		Expires:      now.Add(DefaultLifetime),
		MaxRatePPS:   1000,
		MinRescan:    Duration(time.Hour),
		BumpInterval: Duration(time.Hour),
		Catalog:      catHash,
		Maintainers:  m,
	}
}

func doc(t *testing.T, b Body, signers ...*identity.Key) Document {
	t.Helper()
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	d := Document{Policy: raw}
	for _, k := range signers {
		d.Sign(k)
	}
	return d
}

func accept(t *testing.T, s *State, root Maintainers, d Document) error {
	t.Helper()
	p, err := s.Accept(root, d, now)
	if err == nil {
		s.Latest = &p
	}
	return err
}

func TestAcceptSignatures(t *testing.T) {
	k := keys(t, 3)
	root := set(2, k...)
	var s State
	if err := accept(t, &s, root, doc(t, body(1, root), k[0])); err == nil {
		t.Fatal("one of two needed signatures was accepted")
	}
	d := doc(t, body(1, root), k[0], k[0])
	if err := accept(t, &s, root, d); err == nil {
		t.Fatal("the same key counted twice")
	}
	stranger := keys(t, 1)[0]
	if err := accept(t, &s, root, doc(t, body(1, root), k[0], stranger)); err == nil {
		t.Fatal("a key outside the set counted")
	}
	tampered := doc(t, body(1, root), k[0], k[1])
	tampered.Policy = bytes.Replace(tampered.Policy, []byte(`"pause": false`), []byte(`"pause": true`), 1)
	if err := accept(t, &s, root, tampered); err == nil {
		t.Fatal("an edited body kept its signatures")
	}
	if dropped := tampered.DropInvalid(); len(dropped) != 2 || len(tampered.Signatures) != 0 {
		t.Fatalf("DropInvalid dropped %v", dropped)
	}

	// Relays re-encode the body compactly; the signatures must survive that.
	good := doc(t, body(1, root), k[0], k[1])
	relayed, _ := json.Marshal(good)
	var back Document
	if err := json.Unmarshal(relayed, &back); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(back.Policy, good.Policy) {
		t.Fatal("test needs a relay that changes the whitespace")
	}
	if err := accept(t, &s, root, back); err != nil {
		t.Fatal(err)
	}

	if err := accept(t, &s, root, good); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("replay of the same serial: %v", err)
	}
	if err := accept(t, &s, root, doc(t, body(2, root), k[1], k[2])); err != nil {
		t.Fatal(err)
	}
	if err := accept(t, &s, root, doc(t, body(1, root), k[1], k[2])); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("replay of an older serial: %v", err)
	}
}

func TestEmptyRoot(t *testing.T) {
	k := keys(t, 1)
	if _, err := (State{}).Accept(Maintainers{Threshold: 1}, doc(t, body(1, set(1, k...)), k...), now); err == nil {
		t.Fatal("a build without root keys accepted a policy")
	}
}

func TestParseRejects(t *testing.T) {
	k := keys(t, 1)
	m := set(1, k...)
	for name, edit := range map[string]func(*Body){
		"zero serial":         func(b *Body) { b.Serial = 0 },
		"too long":            func(b *Body) { b.Expires = b.Issued.Add(MaxLifetime + time.Second) },
		"expires first":       func(b *Body) { b.Expires = b.Issued },
		"rate above ceiling":  func(b *Body) { b.MaxRatePPS = 1 << 20 },
		"no rescan budget":    func(b *Body) { b.MinRescan = 0 },
		"bad catalog":         func(b *Body) { b.Catalog = "lab" },
		"bad version":         func(b *Body) { b.MinVersion = "1.2" },
		"bad revoked id":      func(b *Body) { b.RevokedNodes = []Revoked{{ID: "nope"}} },
		"seed with space":     func(b *Body) { b.Seeds = []string{"a b"} },
		"threshold too high":  func(b *Body) { b.Maintainers.Threshold = 2 },
		"no maintainers":      func(b *Body) { b.Maintainers.Keys = nil },
		"duplicate maintaner": func(b *Body) { b.Maintainers.Keys = append(b.Maintainers.Keys, b.Maintainers.Keys[0]) },
	} {
		b := body(1, m)
		b.Maintainers.Keys = slices.Clone(b.Maintainers.Keys)
		edit(&b)
		if _, err := Parse(doc(t, b, k...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := doc(t, body(1, m), k...)
	d.Policy = bytes.Replace(d.Policy, []byte(`"pause"`), []byte(`"pause_all": true, "pause"`), 1)
	if _, err := Parse(d); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestRotation(t *testing.T) {
	k := keys(t, 4)
	root := set(1, k[0])
	next := set(2, k[1], k[2], k[3])
	var s State
	if err := accept(t, &s, root, doc(t, body(1, root), k[0])); err != nil {
		t.Fatal(err)
	}
	if err := accept(t, &s, root, doc(t, body(2, next), k[0])); err == nil {
		t.Fatal("new set took over without signing")
	}
	if err := accept(t, &s, root, doc(t, body(2, next), k[1], k[2])); err == nil {
		t.Fatal("new set took over without the old set")
	}
	if err := accept(t, &s, root, doc(t, body(2, next), k[0], k[1], k[2])); err != nil {
		t.Fatal(err)
	}
	if err := accept(t, &s, root, doc(t, body(3, next), k[0])); err == nil {
		t.Fatal("the retired key still signs alone")
	}
	if err := accept(t, &s, root, doc(t, body(3, next), k[2], k[3])); err != nil {
		t.Fatal(err)
	}
}

func pauseDoc(t *testing.T, serial uint64, d time.Duration, k *identity.Key) Document {
	t.Helper()
	raw, _ := json.Marshal(PauseBody{Serial: serial, Issued: now, Expires: now.Add(d)})
	doc := Document{Pause: raw}
	doc.Sign(k)
	return doc
}

func TestEmergencyPause(t *testing.T) {
	k := keys(t, 3)
	root := set(2, k...)
	var s State
	if err := accept(t, &s, root, doc(t, body(1, root), k[0], k[1])); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptPause(pauseDoc(t, 1, MaxPause+time.Minute, k[2]), now); err == nil {
		t.Fatal("a pause longer than 48h was accepted")
	}
	if _, err := s.AcceptPause(pauseDoc(t, 2, time.Hour, k[2]), now); err == nil {
		t.Fatal("a pause for an unknown policy was accepted")
	}
	if _, err := s.AcceptPause(pauseDoc(t, 1, time.Hour, keys(t, 1)[0]), now); err == nil {
		t.Fatal("a pause by a stranger was accepted")
	}
	p, err := s.AcceptPause(pauseDoc(t, 1, MaxPause, k[2]), now)
	if err != nil {
		t.Fatal(err)
	}
	s.Pause = &p
	if h := s.Halt(now, "v1.0.0", catHash, "x"); !strings.Contains(h, "emergency pause") {
		t.Fatalf("Halt = %q", h)
	}
	if _, err := s.AcceptPause(pauseDoc(t, 1, time.Hour, k[0]), now); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("a second pause for the same policy: %v", err)
	}
	if h := s.Halt(now.Add(MaxPause), "v1.0.0", catHash, "x"); h != "" {
		t.Fatalf("pause outlived 48h: %q", h)
	}
	if err := accept(t, &s, root, doc(t, body(2, root), k[0], k[1])); err != nil {
		t.Fatal(err)
	}
	if h := s.Halt(now, "v1.0.0", catHash, "x"); h != "" {
		t.Fatalf("a newer policy did not end the pause: %q", h)
	}
}

func TestHalt(t *testing.T) {
	k := keys(t, 1)
	m := set(1, k...)
	revoked := keys(t, 1)[0].ID()
	b := body(1, m)
	b.MinVersion = "v0.2.0"
	b.RevokedNodes = []Revoked{{ID: revoked}}
	p, err := Parse(doc(t, b, k...))
	if err != nil {
		t.Fatal(err)
	}
	s := State{Latest: &p}
	paused := p
	paused.Pause = true
	for name, c := range map[string]struct {
		s       State
		at      time.Time
		version string
		catalog string
		self    string
		want    string
	}{
		"in force":        {s, now, "v0.2.0", catHash, "me", ""},
		"newer build":     {s, now, "v0.3.1-4-gabc-dirty", catHash, "me", ""},
		"no policy":       {State{}, now, "v0.2.0", catHash, "me", "no flock policy"},
		"expired":         {s, p.Expires, "v0.2.0", catHash, "me", "expired"},
		"paused":          {State{Latest: &paused}, now, "v0.2.0", catHash, "me", "pauses"},
		"revoked":         {s, now, "v0.2.0", catHash, revoked, "revokes"},
		"old version":     {s, now, "v0.1.9", catHash, "me", "older"},
		"dev build":       {s, now, "dev", catHash, "me", "older"},
		"another catalog": {s, now, "v0.2.0", strings.Repeat("cd", 32), "me", "catalog"},
	} {
		got := c.s.Halt(c.at, c.version, c.catalog, c.self)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: Halt = %q, want %q", name, got, c.want)
		}
	}
}

func TestTrusts(t *testing.T) {
	k := keys(t, 1)
	m := set(1, k...)
	b := body(3, m)
	b.MinVersion = "v0.2.0"
	b.RevokedNodes = []Revoked{{ID: "bad"}}
	p, _ := Parse(doc(t, body(3, m), k...))
	p.Body = b
	s := State{Latest: &p, Expires: map[uint64]time.Time{1: now.Add(-time.Second), 2: now.Add(time.Hour), 3: b.Expires}}
	for name, c := range map[string]struct {
		id, version string
		serial      uint64
		want        bool
	}{
		"same serial":        {"ok", "v0.2.0", 3, true},
		"older, not expired": {"ok", "v0.2.0", 2, true},
		"older, expired":     {"ok", "v0.2.0", 1, false},
		"unknown newer":      {"ok", "v0.2.0", 9, false},
		"no policy":          {"ok", "v0.2.0", 0, false},
		"revoked":            {"bad", "v0.2.0", 3, false},
		"too old":            {"ok", "v0.1.0", 3, false},
	} {
		if got := s.Trusts(c.id, c.version, c.serial, now); got != c.want {
			t.Errorf("%s: Trusts = %v", name, got)
		}
	}
	if !(State{}).Trusts("ok", "dev", 0, now) {
		t.Error("boids without a policy must still trust each other for data")
	}
}

func TestChain(t *testing.T) {
	k := keys(t, 2)
	a, b := set(1, k[0]), set(1, k[1])
	var stored []Policy
	for i, m := range []Maintainers{a, a, b, b, b} {
		p, err := Parse(doc(t, body(uint64(i+1), m), k...))
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, p)
	}
	serials := func(docs []Document) []uint64 {
		var out []uint64
		for _, d := range docs {
			p, _ := Parse(d)
			out = append(out, p.Serial)
		}
		return out
	}
	if got := serials(Chain(stored, 0)); !slices.Equal(got, []uint64{1, 3, 5}) {
		t.Errorf("chain after 0 = %v", got)
	}
	if got := serials(Chain(stored, 3)); !slices.Equal(got, []uint64{5}) {
		t.Errorf("chain after 3 = %v", got)
	}
	if got := Chain(stored, 5); len(got) != 0 {
		t.Errorf("chain after the newest = %v", got)
	}
}

type memStore struct {
	s       State
	revoked []string
}

func (m *memStore) PolicyState(context.Context) (State, error) { return m.s, nil }

func (m *memStore) AddPolicy(_ context.Context, p Policy) (bool, error) {
	if p.Serial <= m.s.Serial() {
		return false, nil
	}
	m.s.Latest = &p
	return true, nil
}

func (m *memStore) AddPause(_ context.Context, p Pause) (bool, error) {
	m.s.Pause = &p
	return true, nil
}

func (m *memStore) SyncRevoked(_ context.Context, ids []string, _ string) error {
	m.revoked = ids
	return nil
}

func TestAdopt(t *testing.T) {
	k := keys(t, 1)
	root := set(1, k...)
	b := body(2, root)
	b.RevokedNodes = []Revoked{{ID: k[0].ID()}}
	pd := pauseDoc(t, 2, time.Hour, k[0])
	st := &memStore{}
	s, changed, err := Adopt(context.Background(), st, root, "me", Bundle{Chain: []Document{doc(t, body(1, root), k...), doc(t, b, k...)}, Pause: &pd}, now)
	if err != nil || !changed || s.Serial() != 2 || !s.Paused(now) {
		t.Fatalf("Adopt = %d, %v, %v", s.Serial(), changed, err)
	}
	if !slices.Equal(st.revoked, []string{k[0].ID()}) {
		t.Fatalf("revoked = %v", st.revoked)
	}
	_, changed, err = Adopt(context.Background(), st, root, "me", Bundle{Chain: []Document{doc(t, body(1, root), k...)}}, now)
	if changed || !errors.Is(err, ErrNotNewer) {
		t.Fatalf("replay: changed %v, %v", changed, err)
	}
	s, changed, err = Adopt(context.Background(), st, root, "me", Bundle{Chain: []Document{doc(t, body(1, root), k...), doc(t, b, k...), doc(t, body(3, root), k...)}}, now)
	if err != nil || !changed || s.Serial() != 3 {
		t.Fatalf("bundle from policy 1 on: %d, %v, %v", s.Serial(), changed, err)
	}
}

func TestBuiltInRoot(t *testing.T) {
	if err := Root.check(); err != nil {
		t.Fatal(err)
	}
}

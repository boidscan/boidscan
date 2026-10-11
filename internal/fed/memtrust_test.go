package fed

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/pkg/client"
)

type memSample struct {
	Sample
	votes   []Vote
	verdict string
	decided time.Time
}

// memTrust keeps samples and checks with the semantics of the Postgres store.
type memTrust struct {
	samples []*memSample
	checks  []*Check
	// peers is the test boid's peer store, where SetTrust writes.
	peers *memStore
}

func (m *memData) AddSample(_ context.Context, s Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.ContainsFunc(m.trust.samples, func(x *memSample) bool { return bytes.Equal(x.Subject, s.Subject) }) {
		return nil
	}
	s.ID, s.CreatedAt = int64(len(m.trust.samples)+1), m.now()
	m.trust.samples = append(m.trust.samples, &memSample{Sample: s})
	return nil
}

func (m *memData) OpenSamples(_ context.Context, limit int) ([]Sample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Sample
	for _, s := range m.trust.samples {
		if s.verdict == "" && len(out) < limit {
			out = append(out, s.Sample)
		}
	}
	return out, nil
}

func (m *memData) sample(id int64) *memSample { return m.trust.samples[id-1] }

func (m *memData) SetCheckers(_ context.Context, id int64, checkers []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sample(id).Checkers = checkers
	return nil
}

func (m *memData) SaveVote(_ context.Context, id int64, v Vote) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sample(id)
	if !slices.ContainsFunc(s.votes, func(x Vote) bool { return x.Checker == v.Checker }) {
		s.votes = append(s.votes, v)
	}
	return nil
}

func (m *memData) Votes(_ context.Context, id int64) ([]Vote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.sample(id).votes), nil
}

func (m *memData) Decide(_ context.Context, id int64, verdict string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sample(id)
	s.verdict, s.decided = verdict, m.now()
	return nil
}

func (m *memData) Score(_ context.Context, scanner string, window int) (Score, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sc Score
	n := 0
	for i := len(m.trust.samples) - 1; i >= 0 && n < window; i-- {
		if s := m.trust.samples[i]; s.Scanner == scanner && s.verdict != "" {
			sc.Add(s.Kind, s.verdict)
			n++
		}
	}
	return sc, nil
}

func (m *memData) CoverageEvidence(_ context.Context, u catalog.Unit, ports []uint16, scanner string, since, before time.Time, limit int) ([]client.Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []client.Observation
	for _, o := range m.obs {
		ip := netip.MustParseAddr(o.IP)
		if u.Block.Contains(ip) && slices.Contains(ports, uint16(o.Port)) && o.Status == "success" && o.NodeID != scanner &&
			!o.SeenAt.Before(since) && o.SeenAt.Before(before) && len(out) < limit {
			out = append(out, o)
		}
	}
	return out, nil
}

func (m *memData) Reported(_ context.Context, scanner string, t CheckTarget, since time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.ContainsFunc(m.obs, func(o client.Observation) bool {
		return o.NodeID == scanner && o.IP == t.IP.String() && o.Port == int(t.Port) && o.Name == t.Name && !o.SeenAt.Before(since)
	}), nil
}

func (m *memData) SetTrust(_ context.Context, id, trust string, lowReach bool) error {
	m.trust.peers.mu.Lock()
	defer m.trust.peers.mu.Unlock()
	if p, ok := m.trust.peers.peers[id]; ok {
		p.Trust, p.LowReach = trust, lowReach
	}
	return nil
}

func (m *memData) DropShunned(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obs = slices.DeleteFunc(m.obs, func(o client.Observation) bool { return o.NodeID == id && !m.confirmed(o) })
	m.dropCoverage(id)
	return nil
}

// confirmed reports whether a sample passed o; the caller holds m.mu.
func (m *memData) confirmed(o client.Observation) bool {
	return slices.ContainsFunc(m.trust.samples, func(s *memSample) bool {
		return bytes.Equal(s.Subject, o.Signature) && (s.verdict == VerdictPass || s.verdict == VerdictChange)
	})
}

func (m *memData) DropCoverage(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropCoverage(id)
	return nil
}

func (m *memData) dropCoverage(id string) {
	m.cov = slices.DeleteFunc(m.cov, func(c Coverage) bool { return c.NodeID == id })
	for u, l := range m.leases {
		if l.holder == id {
			delete(m.leases, u)
		}
	}
}

func (m *memData) AddCheck(_ context.Context, c Check) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.ContainsFunc(m.trust.checks, func(x *Check) bool { return x.Requester == c.Requester && x.Key == c.Key }) {
		return nil
	}
	c.ID = int64(len(m.trust.checks) + 1)
	m.trust.checks = append(m.trust.checks, &c)
	return nil
}

func (m *memData) PendingChecks(_ context.Context, limit int) ([]Check, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Check
	for _, c := range m.trust.checks {
		if !c.Done && len(out) < limit {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (m *memData) FinishCheck(_ context.Context, id int64, r CheckResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.trust.checks[id-1]
	c.Done, c.Result = true, r
	return nil
}

func (m *memData) CheckByKey(_ context.Context, requester, key string) (Check, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.trust.checks {
		if c.Requester == requester && c.Key == key {
			return *c, true, nil
		}
	}
	return Check{}, false, nil
}

// RecentCheck never reuses results in tests, so every vote is a fresh look.
func (m *memData) RecentCheck(context.Context, CheckTarget, time.Time) (CheckResult, bool, error) {
	return CheckResult{}, false, nil
}

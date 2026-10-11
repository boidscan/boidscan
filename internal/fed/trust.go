package fed

import (
	"net/netip"
	"time"

	"github.com/boidscan/boidscan/pkg/client"
)

// Each boid judges every other boid by its own checks; trust is never gossiped.
const (
	TrustProbation = "probation"
	TrustTrusted   = "trusted"
	TrustShunned   = "shunned"
)

// A sample is one reported result that this boid has others check again.
const (
	KindObservation = "observation"
	// KindCoverage samples a unit a scanner reported as scanned: did it miss
	// a service that an earlier scan found there?
	KindCoverage = "coverage"
)

const (
	VerdictPass         = "pass"
	VerdictChange       = "change"
	VerdictContradicted = "contradicted"
	VerdictUnconfirmed  = "unconfirmed"
	VerdictMissed       = "missed"
	VerdictInconclusive = "inconclusive"
)

type TrustConfig struct {
	// TrustAfter is how many passed samples make a peer eligible as a home.
	TrustAfter int
	// Sample rates for results from peers on probation and from trusted peers.
	SampleProbation float64
	SampleTrusted   float64
	// A peer is shunned with at least MinContradicted contradicted samples
	// that are more than MaxContradicted of its decided samples, or more than
	// MaxUnconfirmed unconfirmed observation samples out of at least MinUnconfirmed.
	MinContradicted int
	MaxContradicted float64
	MinUnconfirmed  int
	MaxUnconfirmed  float64
	// A peer has low reach when more than MaxMissed of at least MinReach
	// coverage samples were missed.
	MinReach  int
	MaxMissed float64
	// Window is how many recent samples count, so reach recovers.
	Window int
	// CheckEvery limits how often this boid grabs the same address, port and
	// module; requests in between get the earlier result.
	CheckEvery time.Duration
	// VoteTimeout decides a sample with the votes that arrived by then.
	VoteTimeout time.Duration
}

func DefaultTrust() TrustConfig {
	return TrustConfig{
		TrustAfter: 20, SampleProbation: 0.2, SampleTrusted: 0.01,
		MinContradicted: 3, MaxContradicted: 0.1, MinUnconfirmed: 10, MaxUnconfirmed: 0.5,
		MinReach: 10, MaxMissed: 0.3, Window: 200,
		CheckEvery: 24 * time.Hour, VoteTimeout: 10 * time.Minute,
	}
}

// LabTrust checks every result, so a lab or test flock reaches verdicts in minutes.
func LabTrust() TrustConfig {
	c := DefaultTrust()
	c.TrustAfter, c.SampleProbation, c.SampleTrusted = 2, 1, 1
	c.MinContradicted, c.MinUnconfirmed, c.MinReach = 2, 4, 3
	c.CheckEvery, c.VoteTimeout = 10*time.Second, time.Minute
	return c
}

// Score counts the verdicts on one scanner's recent samples.
type Score struct {
	Pass, Change, Contradicted, Unconfirmed, Missed int
	// CoverageDecided counts decided coverage samples, for reach.
	CoverageDecided int
}

// Add counts one decided sample.
func (s *Score) Add(kind, verdict string) {
	switch verdict {
	case VerdictPass:
		s.Pass++
	case VerdictChange:
		s.Change++
	case VerdictContradicted:
		s.Contradicted++
	case VerdictUnconfirmed:
		s.Unconfirmed++
	case VerdictMissed:
		s.Missed++
	default:
		return
	}
	if kind == KindCoverage {
		s.CoverageDecided++
	}
}

func (s Score) decided() int { return s.Pass + s.Change + s.Contradicted + s.Unconfirmed + s.Missed }

func ratio(n, of int) float64 {
	if of == 0 {
		return 0
	}
	return float64(n) / float64(of)
}

// Assess turns a score into a trust level and reach. Shunning is final.
func (c TrustConfig) Assess(current string, s Score) (string, bool) {
	lowReach := s.CoverageDecided >= c.MinReach && ratio(s.Missed, s.CoverageDecided) > c.MaxMissed
	observed := s.decided() - s.CoverageDecided
	switch {
	case current == TrustShunned,
		s.Contradicted >= c.MinContradicted && ratio(s.Contradicted, s.decided()) > c.MaxContradicted,
		observed >= c.MinUnconfirmed && ratio(s.Unconfirmed, observed) > c.MaxUnconfirmed:
		return TrustShunned, lowReach
	case s.Pass >= c.TrustAfter:
		return TrustTrusted, lowReach
	}
	return TrustProbation, lowReach
}

type CheckTarget struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port"`
	Name string     `json:"name"`
}

// CheckResult is what one boid saw at a target. Unavailable means it could
// not look, for example because its own exclusions cover the address.
type CheckResult struct {
	Open        bool   `json:"open"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Unavailable bool   `json:"unavailable,omitempty"`
}

type Vote struct {
	Checker string `json:"checker"`
	CheckResult
}

type Sample struct {
	ID  int64
	Key string
	// Subject is the signature of the sampled observation or coverage record.
	Subject []byte
	Kind    string
	Scanner string
	Target  CheckTarget
	// What the scanner reported: open with this fingerprint, or nothing.
	ReportedOpen bool
	ReportedFP   string
	// ScannedAt is when the scanner looked: the observation's time, or the
	// start of the unit's scan.
	ScannedAt time.Time
	// Evidence is the signed observation the check is about: the scanner's
	// own, or an earlier one by another boid that the scanner did not repeat.
	Evidence  client.Observation
	Checkers  []string
	CreatedAt time.Time
}

// verdict needs a majority of at least two checkers other than the scanner.
// The scanner's own recheck tells a change at the target from a false or
// incomplete report.
func verdict(s Sample, votes []Vote) string {
	var scanner *Vote
	openFPs := map[string]int{}
	opened, closed := 0, 0
	for _, v := range votes {
		switch {
		case v.Unavailable:
		case v.Checker == s.Scanner:
			scanner = &v
		case v.Open:
			opened++
			openFPs[v.Fingerprint]++
		default:
			closed++
		}
	}
	var open bool
	switch {
	case opened >= 2 && opened > closed:
		open = true
	case closed >= 2 && closed > opened:
	default:
		return VerdictInconclusive
	}
	// The fingerprint counts only when most of the checkers that found the port open saw it.
	fp := ""
	for f, n := range openFPs {
		if 2*n > opened {
			fp = f
		}
	}
	scannerSees := func(open bool) bool {
		return scanner != nil && scanner.Open == open && (!open || scanner.Fingerprint == fp)
	}
	switch {
	case s.Kind == KindCoverage && !open:
		return VerdictPass
	case s.Kind == KindCoverage && scannerSees(true):
		return VerdictChange
	case s.Kind == KindCoverage:
		return VerdictMissed
	case open && (s.ReportedFP == "" || fp == "" || fp == s.ReportedFP):
		return VerdictPass
	case scannerSees(open):
		return VerdictChange
	case open:
		return VerdictContradicted
	}
	return VerdictUnconfirmed
}

// homeEligible picks the peers that may hold blocks: trusted ones, or every
// cooperating one while this boid trusts too few peers to fill a block's homes.
func homeEligible(peers []Peer, replicas int, cooperating func(Peer) bool) func(Peer) bool {
	trusted := 0
	for _, p := range peers {
		if cooperating(p) && p.Trust == TrustTrusted {
			trusted++
		}
	}
	newcomer := trusted < replicas-1
	return func(p Peer) bool {
		return cooperating(p) && p.Trust != TrustShunned && (newcomer || p.Trust == TrustTrusted)
	}
}

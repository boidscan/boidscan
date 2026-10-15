package fed

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/pkg/sig"
)

func (n *Node) policyState() flockpolicy.State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.policy
}

// loadPolicy refreshes the cached policy and logs when this boid starts or
// stops granting leases.
func (n *Node) loadPolicy(ctx context.Context) {
	st, err := n.store.PolicyState(ctx)
	if err != nil {
		slog.Error("loading the flock policy", "err", err)
		return
	}
	halt := st.Halt(n.now(), n.cfg.Version, n.catalogHash, n.cfg.Key.ID())
	n.mu.Lock()
	changed := halt != n.halt || n.ticks == 1
	n.policy, n.halt = st, halt
	n.mu.Unlock()
	switch {
	case !changed:
	case halt != "":
		slog.Warn("the flock does not sweep with me: "+halt, "root", sig.Short(n.rootID))
	default:
		slog.Info("flock policy "+strconv.FormatUint(st.Serial(), 10)+" is in force", "expires", sig.Time(st.Latest.Expires), "min_rescan", time.Duration(st.Latest.MinRescan).String())
	}
}

// cooperates reports whether p may hold blocks, take leases and push results.
func (n *Node) cooperates(st flockpolicy.State, now time.Time) func(Peer) bool {
	return func(p Peer) bool {
		return cooperates(p, n.catalogHash, n.rootID, st, now)
	}
}

func cooperates(p Peer, catalogHash, rootID string, st flockpolicy.State, now time.Time) bool {
	return p.Verified && (p.State == StateAlive || p.State == StateSuspect) && p.Trust != TrustShunned && p.Catalog == catalogHash && p.Root == rootID &&
		st.Trusts(p.ID, p.Version, p.PolicySerial, now)
}

// syncPolicy fetches the policy from one peer that advertises a newer one,
// and from the policy URL once an hour.
func (n *Node) syncPolicy(ctx context.Context, peers []Peer) {
	st := n.policyState()
	now := n.now()
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
	for _, p := range peers {
		if !p.Verified || p.State == StateDown || p.State == StateRevoked || p.Root != n.rootID {
			continue
		}
		newer := p.PolicySerial > st.Serial() || (p.PolicySerial == st.Serial() && p.EmergencyPause && !st.Paused(now))
		key := strconv.FormatUint(p.PolicySerial, 10) + "/" + strconv.FormatBool(p.EmergencyPause)
		n.mu.Lock()
		seen := n.fetched[p.ID] == key
		n.mu.Unlock()
		if !newer || seen {
			continue
		}
		var b flockpolicy.Bundle
		if err := n.call(ctx, http.MethodGet, p.Endpoint+"/fed/v1/policy?after="+strconv.FormatUint(st.Serial(), 10), nil, &b); err != nil {
			slog.Debug("fetching the flock policy failed", "peer", p.Label(), "err", err)
			continue
		}
		n.mu.Lock()
		n.fetched[p.ID] = key
		n.mu.Unlock()
		n.adopt(ctx, b, p.Label())
		break
	}

	n.mu.Lock()
	due := n.cfg.PolicyURL != "" && now.Sub(n.urlFetched) >= policyURLEvery
	if due {
		n.urlFetched = now
	}
	n.mu.Unlock()
	if due {
		var b flockpolicy.Bundle
		if err := n.call(ctx, http.MethodGet, n.cfg.PolicyURL, nil, &b); err != nil {
			slog.Debug("fetching the flock policy URL failed", "url", n.cfg.PolicyURL, "err", err)
			return
		}
		n.adopt(ctx, b, n.cfg.PolicyURL)
	}
}

func (n *Node) adopt(ctx context.Context, b flockpolicy.Bundle, via string) {
	st, changed, err := flockpolicy.Adopt(ctx, n.store, n.cfg.Root, n.cfg.Key.ID(), b, n.now())
	if err != nil && !errors.Is(err, flockpolicy.ErrNotNewer) {
		slog.Warn("rejected a flock policy from "+via, "err", err)
	}
	if !changed {
		return
	}
	slog.Info("adopted flock policy "+strconv.FormatUint(st.Serial(), 10)+" from "+via,
		"expires", sig.Time(st.Latest.Expires), "pause", st.Latest.Pause, "emergency_pause", st.Paused(n.now()), "revoked", len(st.Latest.RevokedNodes))
	n.loadPolicy(ctx)
}

// handlePolicy returns what a boid holding serial ?after= needs to reach this
// boid's policy, and the emergency pause if one is in force.
func (n *Node) handlePolicy(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	ctx := r.Context()
	stored, err := n.store.Policies(ctx)
	if err != nil {
		slog.Error("loading policies", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	st, err := n.store.PolicyState(ctx)
	if err != nil {
		slog.Error("loading the flock policy", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	b := flockpolicy.Bundle{Chain: flockpolicy.Chain(stored, after)}
	if st.Paused(n.now()) {
		b.Pause = &st.Pause.Doc
	}
	writeJSON(w, http.StatusOK, b)
}

type PolicyStatus struct {
	Root    string    `json:"root"`
	Serial  uint64    `json:"serial"`
	Expires time.Time `json:"expires,omitzero"`
	// Halt is why this boid does not sweep or grant leases; empty when it does.
	Halt string `json:"halt,omitempty"`
}

func (n *Node) handlePolicyStatus(w http.ResponseWriter, r *http.Request) {
	st, err := n.store.PolicyState(r.Context())
	if err != nil {
		slog.Error("loading the flock policy", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	s := PolicyStatus{Root: n.rootID, Serial: st.Serial(), Halt: st.Halt(n.now(), n.cfg.Version, n.catalogHash, n.cfg.Key.ID())}
	if st.Latest != nil {
		s.Expires = st.Latest.Expires
	}
	writeJSON(w, http.StatusOK, s)
}

package fed

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/flockpolicy"
	"github.com/boidscan/boidscan/internal/netset"
)

type SweepStore interface {
	Peers(ctx context.Context) ([]Peer, error)
	UnitStatus(ctx context.Context) ([]UnitStatus, error)
	AddCoverage(ctx context.Context, cov []Coverage) (int, error)
	// RecentRun reports whether this boid finished u within the last d.
	RecentRun(ctx context.Context, u catalog.Unit, d time.Duration) (bool, error)
	// RangeExclusions leaves out opted-out addresses: they never cover a whole block.
	RangeExclusions(ctx context.Context) (*netset.Set, error)
	PolicyState(ctx context.Context) (flockpolicy.State, error)
}

type SweepConfig struct {
	Key      Signer
	Name     string
	Endpoint string
	Catalog  catalog.Catalog
	// RootID and Version must match what this boid's serve process advertises.
	RootID       string
	Version      string
	AllowPrivate bool
	// Idle is the wait after a round that found nothing to scan.
	Idle time.Duration
	// Scan scans one unit at no more than maxRate packets per second and
	// returns once its results are stored.
	Scan func(ctx context.Context, u catalog.Unit, maxRate int) error
}

// Sweeper is the worker side of the background sweep: it leases the stalest
// units of its own blocks, or asks other boids for theirs, and scans them.
type Sweeper struct {
	cfg    SweepConfig
	hash   string
	store  SweepStore
	client *http.Client
	now    func() time.Time
	// halt is the last reason not to sweep, kept only to log changes.
	halt string
}

const (
	dueLimit     = 16
	stealFrom    = 3
	minRenewEach = time.Second
)

func NewSweeper(cfg SweepConfig, st SweepStore) *Sweeper {
	if cfg.Idle <= 0 {
		cfg.Idle = time.Minute
	}
	return &Sweeper{cfg: cfg, hash: cfg.Catalog.Hash(), store: st, client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}

func (s *Sweeper) Run(ctx context.Context) {
	idle := false
	for ctx.Err() == nil {
		found, err := s.Step(ctx)
		if err != nil {
			slog.Error("sweeping failed", "err", err)
		}
		if found {
			idle = false
			continue
		}
		if !idle && s.halt == "" {
			slog.Info("nothing is due for a scan; checking again every " + s.cfg.Idle.String())
			idle = true
		}
		select {
		case <-ctx.Done():
		case <-time.After(s.cfg.Idle):
		}
	}
}

// Step leases and scans at most one unit. It reports whether it scanned one.
func (s *Sweeper) Step(ctx context.Context) (bool, error) {
	st, err := s.store.PolicyState(ctx)
	if err != nil {
		return false, err
	}
	now := s.now()
	self := Member{ID: s.cfg.Key.ID(), Name: s.cfg.Name, Endpoint: s.cfg.Endpoint}
	halt := st.Halt(now, s.cfg.Version, s.hash, self.ID)
	if halt != s.halt {
		if halt != "" {
			slog.Warn("sweep halted: " + halt)
		} else {
			slog.Info("sweeping under flock policy "+strconv.FormatUint(st.Serial(), 10)+" at up to "+strconv.Itoa(st.Latest.MaxRatePPS)+" packets/s, rescanning after "+time.Duration(st.Latest.MinRescan).String(), "max_rate", st.Latest.MaxRatePPS, "min_rescan", time.Duration(st.Latest.MinRescan).String())
		}
		s.halt = halt
	}
	if halt != "" {
		return false, nil
	}
	minRescan := time.Duration(st.Latest.MinRescan)
	peers, err := s.store.Peers(ctx)
	if err != nil {
		return false, err
	}
	coop := func(p Peer) bool { return cooperates(p, s.hash, s.cfg.RootID, st, now) }
	v := NewView(self, peers, s.cfg.Catalog, homeEligible(peers, s.cfg.Catalog.Replicas, coop))
	status, err := s.store.UnitStatus(ctx)
	if err != nil {
		return false, err
	}
	all, err := s.store.RangeExclusions(ctx)
	if err != nil {
		return false, err
	}
	// Only prefixes as large as a block can skip one.
	excluded := &netset.Set{}
	for _, p := range all.Prefixes() {
		if p.Bits() <= s.cfg.Catalog.BlockBits {
			excluded.Add(p)
		}
	}
	excluded.AddSet(netset.Reserved(s.cfg.AllowPrivate))
	units := dueUnits(s.cfg.Catalog, v, self.ID, status, excluded, minRescan, now, dueLimit)
	from := "my own blocks"
	if len(units) == 0 {
		units, from = s.steal(ctx, v)
	}
	for _, u := range units {
		if !s.cfg.Catalog.Valid(u) || excluded.Covers(u.Block) {
			continue
		}
		if recent, err := s.store.RecentRun(ctx, u, minRescan); err != nil || recent {
			continue
		}
		homes := v.Homes(u.Block)
		granted, ttl := s.request(ctx, u, homes, false)
		if len(granted)*2 <= len(homes) {
			slog.Debug("no lease, trying the next unit", "unit", u.String(), "granted", len(granted), "homes", len(homes))
			s.request(ctx, u, granted, true)
			continue
		}
		slog.Info("claimed "+u.Describe()+" from "+from+", homes "+strings.Join(names(granted), ", "), "unit", u.String(), "homes", labels(granted))
		return true, s.work(ctx, u, granted, ttl, st.Latest.MaxRatePPS)
	}
	return false, nil
}

// steal asks a few other boids for the stalest units of their blocks.
func (s *Sweeper) steal(ctx context.Context, v View) ([]catalog.Unit, string) {
	others := v.Others()
	rand.Shuffle(len(others), func(i, j int) { others[i], others[j] = others[j], others[i] })
	for _, m := range others[:min(stealFrom, len(others))] {
		var units []catalog.Unit
		if err := call(ctx, s.client, http.MethodGet, m.Endpoint+"/fed/v1/due?limit="+strconv.Itoa(dueLimit), nil, &units); err != nil {
			slog.Debug("asking for due units failed", "peer", m.Label(), "err", err)
			continue
		}
		if len(units) > 0 {
			return units, m.Label()
		}
	}
	return nil, ""
}

// request asks homes to grant, renew or release a lease on u. It returns the
// homes that granted it and the shortest lease they granted.
func (s *Sweeper) request(ctx context.Context, u catalog.Unit, homes []Member, release bool) ([]Member, time.Duration) {
	req := LeaseRequest{Unit: u, Catalog: s.hash, Holder: s.cfg.Key.ID(), Time: s.now().UTC().Truncate(time.Microsecond), Release: release}
	req.Signature = s.cfg.Key.Sign(req.message())
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0
	}
	var mu sync.Mutex
	var granted []Member
	var ttl time.Duration
	var wg sync.WaitGroup
	for _, m := range homes {
		wg.Go(func() {
			var res leaseResponse
			if err := call(ctx, s.client, http.MethodPost, m.Endpoint+"/fed/v1/lease", body, &res); err != nil {
				slog.Debug("lease request failed", "home", m.Label(), "unit", u.String(), "err", err)
				return
			}
			if !res.Granted {
				if !release {
					slog.Debug("lease refused", "home", m.Label(), "unit", u.String(), "reason", res.Reason)
				}
				return
			}
			mu.Lock()
			defer mu.Unlock()
			granted = append(granted, m)
			if d := time.Duration(res.TTL) * time.Second; ttl == 0 || d < ttl {
				ttl = d
			}
		})
	}
	wg.Wait()
	return granted, ttl
}

// work scans u while renewing the lease. Coverage ends the lease at the homes
// once it reaches them; only a failed scan releases it.
func (s *Sweeper) work(ctx context.Context, u catalog.Unit, homes []Member, ttl time.Duration, maxRate int) error {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(max(ttl/3, minRenewEach))
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if renewed, _ := s.request(ctx, u, homes, false); len(renewed)*2 <= len(homes) {
					slog.Warn("could not renew my claim on "+u.Describe()+"; another boid may scan it too", "renewed", len(renewed), "homes", len(homes))
				}
			}
		}
	})
	start := s.now()
	err := s.cfg.Scan(ctx, u, maxRate)
	close(done)
	wg.Wait()
	if err != nil {
		relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		s.request(relCtx, u, homes, true)
		return errors.Join(errors.New("scanning "+u.String()), err)
	}
	if _, err := s.store.AddCoverage(ctx, []Coverage{SignCoverage(s.cfg.Key, u, s.hash, start)}); err != nil {
		return err
	}
	took := s.now().Sub(start)
	if took >= time.Second {
		took = took.Round(time.Second)
	} else {
		took = took.Round(time.Millisecond)
	}
	slog.Info("finished "+u.Describe()+" in "+took.String(), "unit", u.String())
	return nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func names(ms []Member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out
}

func labels(ms []Member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Label()
	}
	return out
}

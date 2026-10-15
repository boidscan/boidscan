package fed

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/sig"
)

const (
	// progressEvery is how many gossip intervals pass between progress counts.
	progressEvery  = 10
	maxScanning    = 256
	hostCountEvery = time.Hour
)

// Progress is one boid's count of the units whose block it is the first home
// of, so that every block is counted by exactly one boid.
type Progress struct {
	NodeID  string    `json:"node_id"`
	Catalog string    `json:"catalog"`
	Time    time.Time `json:"time"`
	// Groups[g] counts the units of port group g.
	Groups    []GroupProgress `json:"groups"`
	Hosts     int64           `json:"hosts"`
	OpenPorts int64           `json:"open_ports"`
	Scanning  []Lease         `json:"scanning"`
}

// GroupProgress counts units scanned ever, within the policy's min_rescan,
// and within the last day.
type GroupProgress struct {
	Ever  int `json:"ever"`
	Fresh int `json:"fresh"`
	Day   int `json:"day"`
}

type Lease struct {
	catalog.Unit
	Holder string `json:"holder"`
}

// HostCount is what this boid stored for one block.
type HostCount struct {
	Hosts     int64
	OpenPorts int64
}

// SignedProgress keeps a Progress as the JSON its boid signed.
type SignedProgress struct {
	Progress  json.RawMessage `json:"progress"`
	Signature []byte          `json:"signature"`
}

func signProgress(k Signer, p Progress) (SignedProgress, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return SignedProgress{}, err
	}
	return SignedProgress{Progress: raw, Signature: k.Sign(sig.JSONMessage("boidscan-progress-v1", raw))}, nil
}

func (s SignedProgress) Open() (Progress, error) {
	var p Progress
	if err := json.Unmarshal(s.Progress, &p); err != nil {
		return p, err
	}
	if !sig.Verify(p.NodeID, sig.JSONMessage("boidscan-progress-v1", s.Progress), s.Signature) {
		return p, errors.New("signature does not match")
	}
	return p, nil
}

// firstHomes maps each block to its first home in v.
func firstHomes(v View, blocks []netip.Prefix) map[netip.Prefix]string {
	out := make(map[netip.Prefix]string, len(blocks))
	for _, b := range blocks {
		if h := v.homes(b); len(h) > 0 {
			out[b] = h[0]
		}
	}
	return out
}

func (n *Node) progressLoop(ctx context.Context) {
	t := time.NewTicker(progressEvery * n.cfg.Interval)
	defer t.Stop()
	for {
		n.RefreshProgress(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshProgress counts this boid's own blocks and fetches the counts of the
// other boids in its view.
func (n *Node) RefreshProgress(ctx context.Context) {
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	p, err := n.ownProgress(ctx, f)
	if err != nil {
		slog.Error("counting progress", "err", err)
		return
	}
	sp, err := signProgress(n.cfg.Key, p)
	if err == nil {
		err = n.cfg.Data.SaveProgress(ctx, p.NodeID, p.Time, sp)
	}
	if err != nil {
		slog.Error("saving progress", "err", err)
		return
	}
	var wg sync.WaitGroup
	for _, m := range f.Others() {
		wg.Go(func() { n.fetchProgress(ctx, m) })
	}
	wg.Wait()

	fp, err := n.FlockProgress(ctx)
	if err != nil {
		slog.Error("summing progress", "err", err)
		return
	}
	msg := fmt.Sprintf("by the counts of %d boids, the flock has scanned %d%% of its catalog", fp.Boids.Reporting, int(fp.PercentEver))
	n.mu.Lock()
	changed := msg != n.progressLog
	n.progressLog = msg
	n.mu.Unlock()
	if changed {
		slog.Info(msg)
	}
}

func (n *Node) ownProgress(ctx context.Context, f flock) (Progress, error) {
	cat := n.cfg.Catalog
	self := n.cfg.Key.ID()
	now := n.now()
	first := firstHomes(f.View, cat.Blocks(netset.Reserved(n.cfg.AllowPrivate)))
	var minRescan time.Duration
	if f.state.Latest != nil {
		minRescan = time.Duration(f.state.Latest.MinRescan)
	}
	var mine []netip.Prefix
	for b, id := range first {
		if id == self {
			mine = append(mine, b)
		}
	}
	status, err := n.cfg.Data.UnitStatus(ctx, mine)
	if err != nil {
		return Progress{}, err
	}
	p := Progress{NodeID: self, Catalog: n.catalogHash, Time: now.UTC().Truncate(time.Microsecond), Groups: make([]GroupProgress, len(cat.Groups)), Scanning: []Lease{}}
	for _, s := range status {
		if first[s.Block] != self || !cat.Valid(s.Unit) {
			continue
		}
		if !s.ScannedAt.IsZero() {
			g := &p.Groups[s.Group]
			g.Ever++
			age := now.Sub(s.ScannedAt)
			if age < minRescan {
				g.Fresh++
			}
			if age < 24*time.Hour {
				g.Day++
			}
		}
		if s.LeasedBy != "" && len(p.Scanning) < maxScanning {
			p.Scanning = append(p.Scanning, Lease{Unit: s.Unit, Holder: s.LeasedBy})
		}
	}
	counts, err := n.hostCounts(ctx, mine)
	if err != nil {
		return Progress{}, err
	}
	for b, c := range counts {
		if first[b] == self {
			p.Hosts += c.Hosts
			p.OpenPorts += c.OpenPorts
		}
	}
	return p, nil
}

// hostCounts reads every stored result in blocks, so it is redone at most
// every hostCountEvery; blocks gained in between count once it is.
func (n *Node) hostCounts(ctx context.Context, blocks []netip.Prefix) (map[netip.Prefix]HostCount, error) {
	n.mu.Lock()
	counts, at := n.hostCountCache, n.hostCountAt
	n.mu.Unlock()
	if counts != nil && n.now().Sub(at) < hostCountEvery {
		return counts, nil
	}
	counts, err := n.cfg.Data.HostCounts(ctx, blocks)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.hostCountCache, n.hostCountAt = counts, n.now()
	n.mu.Unlock()
	return counts, nil
}

func (n *Node) fetchProgress(ctx context.Context, m Member) {
	var sp SignedProgress
	if err := n.call(ctx, http.MethodGet, m.Endpoint+"/fed/v1/progress", nil, &sp); err != nil {
		slog.Debug("fetching progress failed", "peer", m.Label(), "err", err)
		return
	}
	p, err := sp.Open()
	switch {
	case err != nil:
	case p.NodeID != m.ID:
		err = errors.New("signed by another boid")
	case p.Catalog != n.catalogHash || len(p.Groups) != len(n.cfg.Catalog.Groups):
		err = errors.New("another catalog")
	case p.Time.After(n.now().Add(maxClockSkew)):
		err = errors.New("counted in the future")
	}
	if err != nil {
		slog.Warn("ignored the progress count of "+m.Label(), "err", err)
		return
	}
	if err := n.cfg.Data.SaveProgress(ctx, p.NodeID, p.Time, sp); err != nil {
		slog.Error("saving progress", "err", err)
	}
}

func (n *Node) handleProgress(w http.ResponseWriter, r *http.Request) {
	all, err := n.cfg.Data.Progress(r.Context())
	if err != nil {
		slog.Error("loading progress", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	for _, sp := range all {
		if p, err := sp.Open(); err == nil && p.NodeID == n.cfg.Key.ID() {
			writeJSON(w, http.StatusOK, sp)
			return
		}
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not counted yet"})
}

// FlockProgress estimates how much of the catalog the flock has scanned.
type FlockProgress struct {
	Catalog  string    `json:"catalog"`
	AsOf     time.Time `json:"as_of"`
	Estimate bool      `json:"estimate"`
	// FreshWithin is the policy's min_rescan: units scanned within it are not due.
	FreshWithin  string         `json:"fresh_within,omitempty"`
	PercentEver  float64        `json:"percent_ever"`
	PercentFresh float64        `json:"percent_fresh"`
	Units        UnitCounts     `json:"units"`
	Addresses    AddressCounts  `json:"addresses"`
	Hosts        int64          `json:"hosts"`
	OpenPorts    int64          `json:"open_ports"`
	Groups       []GroupSummary `json:"groups"`
	Rate         Rate           `json:"rate"`
	Boids        BoidCounts     `json:"boids"`
	ScanningNow  []ScanningNow  `json:"scanning_now"`
}

type UnitCounts struct {
	Total       int `json:"total"`
	ScannedEver int `json:"scanned_ever"`
	Fresh       int `json:"fresh"`
}

// AddressCounts counts addresses whose block had its core ports scanned.
type AddressCounts struct {
	Total       int64 `json:"total"`
	ScannedEver int64 `json:"scanned_ever"`
}

type GroupSummary struct {
	Group        int     `json:"group"`
	Name         string  `json:"name"`
	Ports        int     `json:"ports"`
	PercentEver  float64 `json:"percent_ever"`
	PercentFresh float64 `json:"percent_fresh"`
}

type Rate struct {
	UnitsLast24h int `json:"units_last_24h"`
	// ETAFullSweep is when every unit will have been scanned once at this rate.
	ETAFullSweep string `json:"eta_full_sweep,omitempty"`
}

type BoidCounts struct {
	Reporting int `json:"reporting"`
	Known     int `json:"known"`
}

type ScanningNow struct {
	Boid  string       `json:"boid"`
	Block netip.Prefix `json:"block"`
	Group int          `json:"group"`
}

func GroupName(g int) string {
	if g == 0 {
		return "core ports"
	}
	return "extra ports " + strconv.Itoa(g)
}

// FlockProgress sums the stored counts of this boid and the boids in its view.
// Each count is capped by the blocks that boid is the first home of in this
// boid's view, so a boid can only inflate its own share.
func (n *Node) FlockProgress(ctx context.Context) (FlockProgress, error) {
	f, err := n.view(ctx)
	if err != nil {
		return FlockProgress{}, err
	}
	stored, err := n.cfg.Data.Progress(ctx)
	if err != nil {
		return FlockProgress{}, err
	}
	cat := n.cfg.Catalog
	now := n.now()
	blocks := cat.Blocks(netset.Reserved(n.cfg.AllowPrivate))
	first := firstHomes(f.View, blocks)
	held := map[string]int{}
	for _, id := range first {
		held[id]++
	}
	size := int64(1) << (32 - cat.BlockBits)
	ports := 0
	for _, g := range cat.Groups {
		ports += len(g)
	}

	out := FlockProgress{Catalog: cat.Name, AsOf: now.UTC().Truncate(time.Second), Estimate: true, ScanningNow: []ScanningNow{}}
	if f.state.Latest != nil {
		out.FreshWithin = time.Duration(f.state.Latest.MinRescan).String()
	}
	out.Boids.Known = len(f.IDs())
	groups := make([]GroupProgress, len(cat.Groups))
	scanning := map[catalog.Unit]string{}
	for _, sp := range stored {
		p, err := sp.Open()
		if err != nil || !f.Has(p.NodeID) || p.Catalog != n.catalogHash || len(p.Groups) != len(cat.Groups) {
			continue
		}
		out.Boids.Reporting++
		limit := held[p.NodeID]
		for g, c := range p.Groups {
			ever := clamp(c.Ever, limit)
			groups[g].Ever += ever
			groups[g].Fresh += clamp(c.Fresh, ever)
			groups[g].Day += clamp(c.Day, ever)
		}
		hosts := clamp(p.Hosts, int64(limit)*size)
		out.Hosts += hosts
		out.OpenPorts += clamp(p.OpenPorts, hosts*int64(ports))
		if now.Sub(p.Time) > 2*progressEvery*n.cfg.Interval {
			continue
		}
		for _, l := range p.Scanning[:min(len(p.Scanning), maxScanning)] {
			if cat.Valid(l.Unit) && first[l.Block] == p.NodeID {
				scanning[l.Unit] = l.Holder
			}
		}
	}

	total := len(blocks)
	for g, c := range groups {
		out.Groups = append(out.Groups, GroupSummary{Group: g, Name: GroupName(g), Ports: len(cat.Groups[g]),
			PercentEver: percent(c.Ever, total), PercentFresh: percent(c.Fresh, total)})
		out.Units.ScannedEver += c.Ever
		out.Units.Fresh += c.Fresh
		out.Rate.UnitsLast24h += c.Day
	}
	out.Units.Total = total * len(cat.Groups)
	out.PercentEver = percent(out.Units.ScannedEver, out.Units.Total)
	out.PercentFresh = percent(out.Units.Fresh, out.Units.Total)
	out.Addresses.Total = int64(total) * size
	if len(groups) > 0 {
		out.Addresses.ScannedEver = int64(groups[0].Ever) * size
	}
	if out.Rate.UnitsLast24h > 0 {
		days := float64(out.Units.Total-out.Units.ScannedEver) / float64(out.Rate.UnitsLast24h)
		out.Rate.ETAFullSweep = eta(days)
	}

	self := n.selfMember()
	for u, holder := range scanning {
		label := sig.Short(holder)
		if holder == self.ID {
			label = self.Label()
		} else if p, ok := f.peers[holder]; ok {
			label = p.Label()
		}
		out.ScanningNow = append(out.ScanningNow, ScanningNow{Boid: label, Block: u.Block, Group: u.Group})
	}
	slices.SortFunc(out.ScanningNow, func(a, b ScanningNow) int {
		return cmp.Or(cmp.Compare(a.Boid, b.Boid), a.Block.Addr().Compare(b.Block.Addr()), cmp.Compare(a.Group, b.Group))
	})
	return out, nil
}

func clamp[T int | int64](v, hi T) T { return max(0, min(v, hi)) }

func percent(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return math.Round(10000*float64(part)/float64(whole)) / 100
}

func eta(days float64) string {
	if days < 2 {
		return strconv.Itoa(int(math.Ceil(days*24))) + "h"
	}
	return strconv.Itoa(int(math.Ceil(days))) + "d"
}

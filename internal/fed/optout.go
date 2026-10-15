package fed

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/sig"
)

const (
	OptOutAdd    = "add"
	OptOutRemove = "remove"
	// MaxOptOutAge is how long an opt-out lasts; the host renews it by asking again.
	MaxOptOutAge = 365 * 24 * time.Hour
	// MaxOptOutsPerDay is how many opt-outs one boid may sign per UTC day, so
	// a rogue boid cannot hide large parts of the internet from the flock.
	MaxOptOutsPerDay = 1000
	optOutsPerHour   = 10
	optOutPage       = 500
	optOutPages      = 20
	optOutListPage   = 1000
	// A peer's opt-out signed by a boid this one does not know yet is retried
	// for this long, then skipped.
	optOutWait = time.Hour
)

// OptOut is a boid's signed statement that the host at IP asked, from that
// address, not to be scanned (add) or to be scanned again (remove). The
// newest statement for an address wins. A remove's Expires only says when it
// stops mattering.
type OptOut struct {
	ID        int64      `json:"id,omitempty"`
	IP        netip.Addr `json:"ip"`
	Action    string     `json:"action"`
	Expires   time.Time  `json:"expires"`
	Signer    string     `json:"signer"`
	Time      time.Time  `json:"time"`
	Signature []byte     `json:"signature"`
}

func (o OptOut) message() []byte {
	return sig.Message("boidscan-optout-v1", o.IP.String(), o.Action, sig.Time(o.Expires), o.Signer, sig.Time(o.Time))
}

func SignOptOut(k Signer, ip netip.Addr, action string, at time.Time) OptOut {
	at = at.UTC().Truncate(time.Microsecond)
	o := OptOut{IP: ip, Action: action, Expires: at.Add(MaxOptOutAge), Signer: k.ID(), Time: at}
	o.Signature = k.Sign(o.message())
	return o
}

// Active reports whether o, as the newest statement for its address, keeps it from being scanned.
func (o OptOut) Active(now time.Time) bool {
	return o.Action == OptOutAdd && o.Expires.After(now)
}

func (o OptOut) Verify() bool { return sig.Verify(o.Signer, o.message(), o.Signature) }

func (o OptOut) valid(now time.Time) bool {
	return o.IP.Is4() && (o.Action == OptOutAdd || o.Action == OptOutRemove) &&
		o.Expires.After(o.Time) && o.Expires.Sub(o.Time) <= MaxOptOutAge && !o.Time.After(now.Add(maxClockSkew))
}

type OptOutData interface {
	// AddOptOuts stores attestations it does not have yet, at most
	// MaxOptOutsPerDay per signer and UTC day, and deletes stored results for
	// addresses that are opted out afterwards. capped counts the ones over the limit.
	AddOptOuts(ctx context.Context, list []OptOut) (stored, capped int, err error)
	// OptOutsAfter returns stored attestations in id order.
	OptOutsAfter(ctx context.Context, after int64, limit int) ([]OptOut, error)
	// ActiveOptOuts lists, in address order, the newest attestation of up to
	// limit addresses above after that are opted out now. An invalid after starts at the lowest.
	ActiveOptOuts(ctx context.Context, after netip.Addr, limit int) ([]OptOut, error)
	LatestOptOut(ctx context.Context, ip netip.Addr) (OptOut, bool, error)
	// OptOutRequests counts the attestations signer made for ip since the given time.
	OptOutRequests(ctx context.Context, signer string, ip netip.Addr, since time.Time) (int, error)
	OptOutCursor(ctx context.Context, peer string) (int64, error)
	SaveOptOutCursor(ctx context.Context, peer string, after int64) error
}

var (
	ErrOptOutAddress = errors.New("opt-outs cover public IPv4 addresses only, and this request did not come from one")
	ErrOptOutRate    = errors.New("too many opt-out requests from this address, try again in an hour")
	ErrOptOutFull    = errors.New("this boid has signed as many opt-outs as it may today, ask another boid")
	ErrNotOptedOut   = errors.New("this address is not opted out")
)

// OptOutDesk takes opt-out requests from hosts at this boid's public API.
type OptOutDesk struct {
	key      Signer
	data     OptOutData
	reserved *netset.Set
	now      func() time.Time
}

func NewOptOutDesk(k Signer, d OptOutData, allowPrivate bool) *OptOutDesk {
	return &OptOutDesk{key: k, data: d, reserved: netset.Reserved(allowPrivate), now: time.Now}
}

// Status returns the newest attestation for ip and whether it is active.
func (d *OptOutDesk) Status(ctx context.Context, ip netip.Addr) (OptOut, bool, error) {
	o, ok, err := d.data.LatestOptOut(ctx, ip)
	return o, ok && o.Active(d.now()), err
}

// Request signs an opt-out (add) or its withdrawal (remove) for ip, the
// address the request came from.
func (d *OptOutDesk) Request(ctx context.Context, ip netip.Addr, action string) (OptOut, error) {
	if !ip.Is4() || d.reserved.Contains(ip) {
		return OptOut{}, ErrOptOutAddress
	}
	now := d.now()
	n, err := d.data.OptOutRequests(ctx, d.key.ID(), ip, now.Add(-time.Hour))
	if err != nil {
		return OptOut{}, err
	}
	if n >= optOutsPerHour {
		return OptOut{}, ErrOptOutRate
	}
	if action == OptOutRemove {
		_, active, err := d.Status(ctx, ip)
		if err != nil {
			return OptOut{}, err
		}
		if !active {
			return OptOut{}, ErrNotOptedOut
		}
	}
	o := SignOptOut(d.key, ip, action, now)
	_, capped, err := d.data.AddOptOuts(ctx, []OptOut{o})
	if err != nil {
		return OptOut{}, err
	}
	if capped > 0 {
		slog.Warn("I turned away an opt-out from " + ip.String() + ": I already signed " + strconv.Itoa(MaxOptOutsPerDay) + " today")
		return OptOut{}, ErrOptOutFull
	}
	if action == OptOutAdd {
		slog.Info(ip.String() + " asked not to be scanned; I signed its opt-out until " + o.Expires.Format(time.DateOnly))
	} else {
		slog.Info(ip.String() + " withdrew its opt-out")
	}
	return o, nil
}

// SyncOptOuts reads the opt-out logs of a few peers. Every boid passes on
// what it accepted, so an opt-out reaches the whole flock like gossip.
func (n *Node) SyncOptOuts(ctx context.Context) {
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	var from []Peer
	for _, p := range f.peers {
		if p.Verified && p.State != StateDown && p.State != StateRevoked && !f.rejects(p.ID) {
			from = append(from, p)
		}
	}
	rand.Shuffle(len(from), func(i, j int) { from[i], from[j] = from[j], from[i] })
	for _, p := range from[:min(fanout, len(from))] {
		if err := n.pullOptOuts(ctx, f, p); err != nil {
			slog.Error("reading opt-outs from "+p.Label(), "err", err)
		}
	}
}

func (n *Node) pullOptOuts(ctx context.Context, f flock, p Peer) error {
	after, err := n.cfg.Data.OptOutCursor(ctx, p.ID)
	if err != nil {
		return err
	}
	var stored, capped, rejected int
	for range optOutPages {
		var page []OptOut
		if err := n.call(ctx, http.MethodGet, p.Endpoint+"/fed/v1/optouts/log?after="+strconv.FormatInt(after, 10), nil, &page); err != nil {
			slog.Debug("reading opt-outs failed", "peer", p.Label(), "err", err)
			break
		}
		accept, next, bad, wait := n.screenOptOuts(f, page, after)
		s, c, err := n.cfg.Data.AddOptOuts(ctx, accept)
		if err != nil {
			return err
		}
		stored, capped, rejected = stored+s, capped+c, rejected+bad
		if next != after {
			if err := n.cfg.Data.SaveOptOutCursor(ctx, p.ID, next); err != nil {
				return err
			}
			after = next
		}
		if wait || len(page) < optOutPage {
			break
		}
	}
	if stored > 0 {
		slog.Info("I learned " + optOutCount(stored) + " from " + p.Label())
	}
	if capped > 0 {
		slog.Warn("I refused " + optOutCount(capped) + " from " + p.Label() + " signed by a boid that signed more than " + strconv.Itoa(MaxOptOutsPerDay) + " in one day")
	}
	if rejected > 0 {
		slog.Warn("I refused " + optOutCount(rejected) + " from " + p.Label() + ": bad signature, invalid, or signed by a boid I do not accept")
	}
	return nil
}

func optOutCount(n int) string {
	if n == 1 {
		return "1 opt-out"
	}
	return strconv.Itoa(n) + " opt-outs"
}

// screenOptOuts picks the attestations of a page to store and the cursor to
// continue from. It stops early, with wait set, at a recent attestation
// signed by a boid this one has not verified yet.
func (n *Node) screenOptOuts(f flock, page []OptOut, after int64) (accept []OptOut, next int64, rejected int, wait bool) {
	now := n.now()
	next = after
	for _, o := range page {
		if o.ID <= next {
			continue
		}
		p, known := f.peers[o.Signer]
		switch {
		case o.Signer == f.self:
		case f.rejects(o.Signer):
			rejected++
			next = o.ID
			continue
		case (!known || !p.Verified) && now.Sub(o.Time) < optOutWait:
			return accept, next, rejected, true
		case !known || !p.Verified:
			next = o.ID
			continue
		}
		next = o.ID
		switch {
		case !o.valid(now) || !o.Verify():
			rejected++
		case o.Expires.After(now):
			accept = append(accept, o)
		}
	}
	return accept, next, rejected, false
}

// handleOptOuts lists the opt-outs in force, for anyone to audit, a page at a
// time: ?after=<last address of the previous page>.
func (n *Node) handleOptOuts(w http.ResponseWriter, r *http.Request) {
	after, _ := netip.ParseAddr(r.URL.Query().Get("after"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > optOutListPage {
		limit = optOutListPage
	}
	list, err := n.cfg.Data.ActiveOptOuts(r.Context(), after, limit)
	if err != nil {
		slog.Error("loading opt-outs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if list == nil {
		list = []OptOut{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleOptOutLog returns stored attestations after ?after= in id order, for other boids to copy.
func (n *Node) handleOptOutLog(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	list, err := n.cfg.Data.OptOutsAfter(r.Context(), after, optOutPage)
	if err != nil {
		slog.Error("loading opt-outs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if list == nil {
		list = []OptOut{}
	}
	writeJSON(w, http.StatusOK, list)
}

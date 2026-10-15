package fed

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/boidscan/boidscan/internal/catalog"
	"github.com/boidscan/boidscan/internal/grab"
	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/client"
	"github.com/boidscan/boidscan/pkg/sig"
)

const (
	checkBatch    = 64
	sampleBatch   = 200
	evidenceSince = 30 * 24 * time.Hour
	evidenceLimit = 50
)

// Check is a grab this boid runs for itself or for another boid's sample.
type Check struct {
	ID        int64
	Requester string
	Key       string
	Kind      string
	Scanner   string
	Target    CheckTarget
	Evidence  client.Observation
	Done      bool
	Result    CheckResult
}

// TrustData keeps samples, votes, checks and the trust they lead to.
type TrustData interface {
	// AddSample stores s unless its subject was sampled before.
	AddSample(ctx context.Context, s Sample) error
	OpenSamples(ctx context.Context, limit int) ([]Sample, error)
	SetCheckers(ctx context.Context, id int64, checkers []string) error
	SaveVote(ctx context.Context, id int64, v Vote) error
	Votes(ctx context.Context, id int64) ([]Vote, error)
	Decide(ctx context.Context, id int64, verdict string) error
	// Score counts the verdicts on the scanner's last window decided samples.
	Score(ctx context.Context, scanner string, window int) (Score, error)
	// CoverageEvidence lists successful observations in u's block on the given
	// ports by boids other than scanner, seen between since and before.
	CoverageEvidence(ctx context.Context, u catalog.Unit, ports []uint16, scanner string, since, before time.Time, limit int) ([]client.Observation, error)
	// Reported says whether scanner has an observation of t seen after since.
	Reported(ctx context.Context, scanner string, t CheckTarget, since time.Time) (bool, error)
	SetTrust(ctx context.Context, id, trust string, lowReach bool) error
	// DropShunned deletes id's coverage, leases, opt-outs and every result of id that
	// no sample of this boid confirmed.
	DropShunned(ctx context.Context, id string) error
	DropCoverage(ctx context.Context, id string) error

	// AddCheck stores c unless the requester already asked under the same key.
	AddCheck(ctx context.Context, c Check) error
	PendingChecks(ctx context.Context, limit int) ([]Check, error)
	FinishCheck(ctx context.Context, id int64, r CheckResult) error
	CheckByKey(ctx context.Context, requester, key string) (Check, bool, error)
	// RecentCheck returns this boid's last finished grab of t since then.
	RecentCheck(ctx context.Context, t CheckTarget, since time.Time) (CheckResult, bool, error)
}

func target(o client.Observation) (CheckTarget, error) {
	ip, err := netip.ParseAddr(o.IP)
	if err != nil || o.Port < 1 || o.Port > 65535 {
		return CheckTarget{}, errors.New("invalid target")
	}
	return CheckTarget{IP: ip, Port: uint16(o.Port), Name: o.Name}, nil
}

// sampleRows picks pushed results to have checked: scanners on probation
// more often than trusted ones. Samples are chosen here, unpredictably for
// the scanner, whose signatures are deterministic.
func (n *Node) sampleRows(ctx context.Context, f flock, obs []client.Observation, cov []Coverage) {
	self := n.cfg.Key.ID()
	rate := func(id string) float64 {
		if p, ok := f.peers[id]; ok && p.Trust == TrustTrusted {
			return n.cfg.Trust.SampleTrusted
		}
		return n.cfg.Trust.SampleProbation
	}
	for _, o := range obs {
		if o.NodeID == self || o.Status != "success" || rand.Float64() >= rate(o.NodeID) {
			continue
		}
		t, err := target(o)
		if err != nil {
			continue
		}
		n.addSample(ctx, Sample{Kind: KindObservation, Subject: o.Signature, Scanner: o.NodeID, Target: t, ReportedOpen: true,
			ReportedFP: grab.Fingerprint(o.Data), ScannedAt: o.SeenAt, Evidence: o})
	}
	for _, c := range cov {
		if c.NodeID == self || rand.Float64() >= rate(c.NodeID) {
			continue
		}
		evidence, err := n.cfg.Data.CoverageEvidence(ctx, c.Unit(), n.cfg.Catalog.Ports(c.Group), c.NodeID, c.ScannedAt.Add(-evidenceSince), c.ScannedAt, evidenceLimit)
		if err != nil || len(evidence) == 0 {
			continue
		}
		rand.Shuffle(len(evidence), func(i, j int) { evidence[i], evidence[j] = evidence[j], evidence[i] })
		pick := evidence[0]
		// Prefer a service the scanner did not report; the others would pass anyway.
		for _, e := range evidence {
			t, err := target(e)
			if err != nil {
				continue
			}
			if reported, err := n.cfg.Data.Reported(ctx, c.NodeID, t, c.ScannedAt); err == nil && !reported {
				pick = e
				break
			}
		}
		t, err := target(pick)
		if err != nil {
			continue
		}
		n.addSample(ctx, Sample{Kind: KindCoverage, Subject: c.Signature, Scanner: c.NodeID, Target: t, ScannedAt: c.ScannedAt, Evidence: pick})
	}
}

func (n *Node) addSample(ctx context.Context, s Sample) {
	s.Key = crand.Text()
	if err := n.cfg.Data.AddSample(ctx, s); err != nil {
		slog.Error("storing a sample", "err", err)
	}
}

// trustLoop runs the grabs other boids asked for and moves this boid's own
// samples towards a verdict.
func (n *Node) trustLoop(ctx context.Context) {
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		n.RunChecks(ctx)
		n.AdvanceSamples(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunChecks grabs the targets of pending checks once each.
func (n *Node) RunChecks(ctx context.Context) {
	if n.cfg.Check == nil {
		return
	}
	pending, err := n.cfg.Data.PendingChecks(ctx, checkBatch)
	if err != nil || len(pending) == 0 {
		if err != nil {
			slog.Error("loading checks", "err", err)
		}
		return
	}
	var targets []CheckTarget
	reserved := netset.Reserved(n.cfg.AllowPrivate)
	for _, c := range pending {
		excluded, err := n.cfg.Data.Excluded(ctx, c.Target.IP)
		if err != nil || excluded || reserved.Contains(c.Target.IP) || !n.cfg.Catalog.Contains(c.Target.IP) {
			n.finishCheck(ctx, c, CheckResult{Unavailable: true})
			continue
		}
		if !slices.Contains(targets, c.Target) {
			targets = append(targets, c.Target)
		}
	}
	if len(targets) == 0 {
		return
	}
	results, err := n.cfg.Check(ctx, targets)
	if err != nil {
		slog.Warn("checking results of other boids failed", "targets", len(targets), "err", err)
		return
	}
	for _, c := range pending {
		if i := slices.Index(targets, c.Target); i >= 0 && i < len(results) {
			n.finishCheck(ctx, c, results[i])
		}
	}
	slog.Debug("checked targets for samples", "targets", len(targets), "checks", len(pending))
}

func (n *Node) finishCheck(ctx context.Context, c Check, r CheckResult) {
	if err := n.cfg.Data.FinishCheck(ctx, c.ID, r); err != nil {
		slog.Error("storing a check result", "err", err)
	}
}

// forged is what a boid run with -forge claims when asked about its own
// reports: that they were right.
func (n *Node) forged(c Check) (CheckResult, bool) {
	if !n.cfg.Forge || c.Scanner != n.cfg.Key.ID() {
		return CheckResult{}, false
	}
	if c.Kind == KindCoverage {
		return CheckResult{}, true
	}
	return CheckResult{Open: true, Fingerprint: grab.Fingerprint(c.Evidence.Data)}, true
}

// AdvanceSamples asks for votes on new samples, collects votes and decides.
func (n *Node) AdvanceSamples(ctx context.Context) {
	samples, err := n.cfg.Data.OpenSamples(ctx, sampleBatch)
	if err != nil || len(samples) == 0 {
		if err != nil {
			slog.Error("loading samples", "err", err)
		}
		return
	}
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		return
	}
	var wg sync.WaitGroup
	for _, s := range samples {
		wg.Go(func() {
			if s.Checkers == nil {
				n.requestVotes(ctx, f, s)
			} else {
				n.collectVotes(ctx, f, s)
			}
		})
	}
	wg.Wait()
}

type checkRequest struct {
	Key      string             `json:"key"`
	Kind     string             `json:"kind"`
	Scanner  string             `json:"scanner"`
	Evidence client.Observation `json:"evidence"`
}

// requestVotes asks the other homes of the block and the scanner itself to
// look at the target, and looks itself.
func (n *Node) requestVotes(ctx context.Context, f flock, s Sample) {
	self := n.cfg.Key.ID()
	var asked []Member
	for _, m := range f.Homes(n.cfg.Catalog.Block(s.Target.IP)) {
		if m.ID != self && m.ID != s.Scanner {
			asked = append(asked, m)
		}
	}
	if p, ok := f.peers[s.Scanner]; ok && p.Verified && p.State != StateRevoked {
		asked = append(asked, Member{ID: p.ID, Name: p.Name, Endpoint: p.Endpoint})
	}
	body, err := json.Marshal(checkRequest{Key: s.Key, Kind: s.Kind, Scanner: s.Scanner, Evidence: s.Evidence})
	if err != nil {
		return
	}
	checkers := []string{self}
	n.queueCheck(ctx, Check{Requester: self, Key: s.Key, Kind: s.Kind, Scanner: s.Scanner, Target: s.Target, Evidence: s.Evidence})
	for _, m := range asked {
		var res struct{}
		if err := n.signedCall(ctx, http.MethodPost, m.Endpoint+"/fed/v1/check", body, &res); err != nil {
			slog.Debug("check request refused", "peer", m.Label(), "err", err)
			continue
		}
		checkers = append(checkers, m.ID)
	}
	if err := n.cfg.Data.SetCheckers(ctx, s.ID, checkers); err != nil {
		slog.Error("storing checkers", "err", err)
	}
}

// queueCheck stores a check, answered at once from a recent grab of the same
// target, so no address is grabbed more often than CheckEvery.
func (n *Node) queueCheck(ctx context.Context, c Check) {
	if r, ok := n.forged(c); ok {
		c.Done, c.Result = true, r
	} else if r, ok, err := n.cfg.Data.RecentCheck(ctx, c.Target, n.now().Add(-n.cfg.Trust.CheckEvery)); err == nil && ok {
		c.Done, c.Result = true, r
	}
	if err := n.cfg.Data.AddCheck(ctx, c); err != nil {
		slog.Error("storing a check", "err", err)
	}
}

func (n *Node) collectVotes(ctx context.Context, f flock, s Sample) {
	votes, err := n.cfg.Data.Votes(ctx, s.ID)
	if err != nil {
		slog.Error("loading votes", "err", err)
		return
	}
	self := n.cfg.Key.ID()
	for _, id := range s.Checkers {
		if slices.ContainsFunc(votes, func(v Vote) bool { return v.Checker == id }) {
			continue
		}
		var r CheckResult
		if id == self {
			c, ok, err := n.cfg.Data.CheckByKey(ctx, self, s.Key)
			if err != nil || !ok || !c.Done {
				continue
			}
			r = c.Result
		} else {
			p, ok := f.peers[id]
			if !ok {
				continue
			}
			var resp checkResponse
			if err := n.signedCall(ctx, http.MethodGet, p.Endpoint+"/fed/v1/check/"+url.PathEscape(s.Key), nil, &resp); err != nil {
				slog.Debug("collecting a vote failed", "peer", p.Label(), "err", err)
				continue
			}
			if !resp.Done || !sig.Verify(id, voteMessage(s.Key, id, resp.CheckResult), resp.Signature) {
				continue
			}
			r = resp.CheckResult
		}
		v := Vote{Checker: id, CheckResult: r}
		if err := n.cfg.Data.SaveVote(ctx, s.ID, v); err != nil {
			slog.Error("storing a vote", "err", err)
			return
		}
		votes = append(votes, v)
	}
	if len(votes) < len(s.Checkers) && n.now().Sub(s.CreatedAt) < n.cfg.Trust.VoteTimeout {
		return
	}
	n.decide(ctx, f, s, votes)
}

func (n *Node) decide(ctx context.Context, f flock, s Sample, votes []Vote) {
	v := verdict(s, votes)
	// The scanner's results may have arrived after its coverage.
	if v == VerdictMissed {
		if reported, err := n.cfg.Data.Reported(ctx, s.Scanner, s.Target, s.ScannedAt); err == nil && reported {
			v = VerdictPass
		}
	}
	if err := n.cfg.Data.Decide(ctx, s.ID, v); err != nil {
		slog.Error("storing a verdict", "err", err)
		return
	}
	label := sig.Short(s.Scanner)
	if p, ok := f.peers[s.Scanner]; ok {
		label = p.Label()
	}
	level := slog.LevelDebug
	if v != VerdictPass && v != VerdictInconclusive {
		level = slog.LevelInfo
	}
	slog.Log(ctx, level, "checked a "+s.Kind+" of "+label+": "+v, "target", s.Target.IP.String()+":"+strconv.Itoa(int(s.Target.Port))+" "+s.Target.Name, "votes", len(votes))
	n.reassess(ctx, f, s.Scanner, label)
}

// reassess updates a scanner's trust after a verdict and drops what this
// boid no longer accepts from it.
func (n *Node) reassess(ctx context.Context, f flock, id, label string) {
	p, known := f.peers[id]
	cur, curLow := TrustProbation, false
	if known {
		cur, curLow = p.Trust, p.LowReach
	}
	score, err := n.cfg.Data.Score(ctx, id, n.cfg.Trust.Window)
	if err != nil {
		slog.Error("scoring a peer", "err", err)
		return
	}
	trust, low := n.cfg.Trust.Assess(cur, score)
	if !known || (trust == cur && low == curLow) {
		return
	}
	if err := n.cfg.Data.SetTrust(ctx, id, trust, low); err != nil {
		slog.Error("storing trust", "err", err)
		return
	}
	detail := []any{"pass", score.Pass, "change", score.Change, "contradicted", score.Contradicted, "unconfirmed", score.Unconfirmed, "missed", score.Missed}
	switch {
	case trust == TrustShunned && cur != TrustShunned:
		slog.Warn("shunned "+label+": other boids contradict its results; dropping what nobody confirmed", detail...)
		if err := n.cfg.Data.DropShunned(ctx, id); err != nil {
			slog.Error("dropping a shunned boid's results", "err", err)
		}
	case trust != cur:
		slog.Info(label+" is now "+trust, detail...)
	}
	switch {
	case low && !curLow:
		slog.Warn(label+" misses too much that others see, probably blocked by many hosts; its coverage no longer counts", detail...)
		if err := n.cfg.Data.DropCoverage(ctx, id); err != nil {
			slog.Error("dropping coverage", "err", err)
		}
	case !low && curLow:
		slog.Info(label+" reaches enough hosts again", detail...)
	}
}

func voteMessage(key, checker string, r CheckResult) []byte {
	return sig.Message("boidscan-vote-v1", key, checker, strconv.FormatBool(r.Open), r.Fingerprint, strconv.FormatBool(r.Unavailable))
}

type checkResponse struct {
	Done bool `json:"done"`
	CheckResult
	Signature []byte `json:"signature,omitempty"`
}

// handleCheck queues a grab for a sample of another boid. The target must be
// a signed result, so no boid can point this one at an arbitrary address,
// and a recent grab of the same target is reused.
func (n *Node) handleCheck(w http.ResponseWriter, r *http.Request) {
	body, sender, err := n.signedBody(w, r, 1<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var req checkRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Key == "" || len(req.Key) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid check request"})
		return
	}
	ctx := r.Context()
	f, err := n.view(ctx)
	if err != nil {
		slog.Error("loading peers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !f.cooperating(sender) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "this boid does not work with the sender"})
		return
	}
	t, err := target(req.Evidence)
	if err != nil || req.Evidence.Verify() != nil || !n.cfg.Catalog.Contains(t.IP) || netset.Reserved(n.cfg.AllowPrivate).Contains(t.IP) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the evidence is not a signed result in this flock's range"})
		return
	}
	n.queueCheck(ctx, Check{Requester: sender, Key: req.Key, Kind: req.Kind, Scanner: req.Scanner, Target: t, Evidence: req.Evidence})
	writeJSON(w, http.StatusOK, struct{}{})
}

func (n *Node) handleCheckResult(w http.ResponseWriter, r *http.Request) {
	_, sender, err := n.signedBody(w, r, 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	key := r.PathValue("key")
	c, ok, err := n.cfg.Data.CheckByKey(r.Context(), sender, key)
	if err != nil {
		slog.Error("loading a check", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such check"})
		return
	}
	resp := checkResponse{Done: c.Done}
	if c.Done {
		resp.CheckResult = c.Result
		resp.Signature = n.cfg.Key.Sign(voteMessage(key, n.cfg.Key.ID(), c.Result))
	}
	writeJSON(w, http.StatusOK, resp)
}

const (
	headerNode      = "X-Boidscan-Node"
	headerTime      = "X-Boidscan-Time"
	headerSignature = "X-Boidscan-Signature"
)

// signedCall is call with the request signed by this boid's key.
func (n *Node) signedCall(ctx context.Context, method, rawURL string, body []byte, out any) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	now := n.now()
	h := http.Header{}
	h.Set(headerNode, n.cfg.Key.ID())
	h.Set(headerTime, sig.Time(now))
	h.Set(headerSignature, base64.StdEncoding.EncodeToString(n.cfg.Key.Sign(sig.RequestMessage(method, u.EscapedPath(), now, body))))
	return callWith(ctx, n.client, method, rawURL, body, h, out)
}

// signedBody reads a request body of at most limit bytes and returns it with
// the ID of the boid that signed the request.
func (n *Node) signedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, string, error) {
	var body []byte
	if limit > 0 {
		var err error
		if body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit)); err != nil {
			return nil, "", errors.New("request too large")
		}
	}
	id := r.Header.Get(headerNode)
	at, err := time.Parse("2006-01-02T15:04:05.000000Z", r.Header.Get(headerTime))
	if err != nil {
		return nil, "", errors.New("request is not signed")
	}
	if d := n.now().Sub(at); d > maxClockSkew || d < -maxClockSkew {
		return nil, "", errors.New("request time too far from this boid's clock")
	}
	signature, err := base64.StdEncoding.DecodeString(r.Header.Get(headerSignature))
	if err != nil || !sig.Verify(id, sig.RequestMessage(r.Method, r.URL.EscapedPath(), at, body), signature) {
		return nil, "", errors.New("request signature does not match")
	}
	return body, id, nil
}

func callWith(ctx context.Context, c *http.Client, method, url string, body []byte, h http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("%s: %s %s", url, res.Status, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxPushBody)).Decode(out)
}

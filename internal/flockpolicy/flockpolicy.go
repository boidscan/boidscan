// Package flockpolicy reads, checks and applies the flock policy: the
// document, signed by the maintainers, that sets the rules every boid in the
// flock follows. Boids without a valid policy do not sweep.
package flockpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/boidscan/boidscan/internal/policy"
	"github.com/boidscan/boidscan/pkg/sig"
)

const (
	DefaultLifetime = 14 * 24 * time.Hour
	// MaxLifetime bounds the damage of a stolen threshold of keys.
	MaxLifetime = 31 * 24 * time.Hour
	MaxPause    = 48 * time.Hour

	maxClockSkew = 2 * time.Minute
	policyTag    = "boidscan-policy-v1"
	pauseTag     = "boidscan-pause-v1"
)

// ErrNotNewer marks a document the boid already has or has passed.
var ErrNotNewer = errors.New("not newer than the policy this boid holds")

type Signer interface {
	ID() string
	Sign([]byte) []byte
}

// Duration is written as Go duration text, e.g. "168h".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

type Maintainers struct {
	Keys      []string `json:"keys"`
	Threshold int      `json:"threshold"`
}

func (m Maintainers) check() error {
	if len(m.Keys) == 0 {
		return errors.New("no maintainer keys")
	}
	if m.Threshold < 1 || m.Threshold > len(m.Keys) {
		return fmt.Errorf("threshold %d: want 1 to %d", m.Threshold, len(m.Keys))
	}
	seen := map[string]bool{}
	for _, k := range m.Keys {
		if _, err := sig.DecodeID(k); err != nil {
			return fmt.Errorf("maintainer key %q: %w", k, err)
		}
		if seen[k] {
			return fmt.Errorf("maintainer key %s listed twice", k)
		}
		seen[k] = true
	}
	return nil
}

func (m Maintainers) Equal(o Maintainers) bool {
	return m.Threshold == o.Threshold && slices.Equal(slices.Sorted(slices.Values(m.Keys)), slices.Sorted(slices.Values(o.Keys)))
}

// ID names a root maintainer set. Boids form a flock only with peers that
// have the same root.
func (m Maintainers) ID() string {
	fields := append([]string{strconv.Itoa(m.Threshold)}, slices.Sorted(slices.Values(m.Keys))...)
	sum := sha256.Sum256(sig.Message("boidscan-root-v1", fields...))
	return hex.EncodeToString(sum[:])
}

// String is the form ParseRoot reads: "key,key:threshold".
func (m Maintainers) String() string {
	return strings.Join(m.Keys, ",") + ":" + strconv.Itoa(m.Threshold)
}

// ParseRoot reads "key,key:threshold"; without a threshold every key must sign.
func ParseRoot(s string) (Maintainers, error) {
	keys, k, hasK := strings.Cut(strings.TrimSpace(s), ":")
	m := Maintainers{}
	for _, key := range strings.Split(keys, ",") {
		if key = strings.TrimSpace(key); key != "" {
			m.Keys = append(m.Keys, key)
		}
	}
	m.Threshold = len(m.Keys)
	if hasK {
		n, err := strconv.Atoi(k)
		if err != nil {
			return m, fmt.Errorf("threshold %q: %w", k, err)
		}
		m.Threshold = n
	}
	return m, m.check()
}

type Revoked struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
	Issue  string `json:"issue,omitempty"`
}

type Body struct {
	Serial       uint64      `json:"serial"`
	Issued       time.Time   `json:"issued"`
	Expires      time.Time   `json:"expires"`
	Pause        bool        `json:"pause"`
	MinVersion   string      `json:"min_version"`
	MaxRatePPS   int         `json:"max_rate_pps"`
	MinRescan    Duration    `json:"min_rescan"`
	BumpInterval Duration    `json:"bump_interval"`
	Catalog      string      `json:"catalog"`
	RevokedNodes []Revoked   `json:"revoked_nodes"`
	Seeds        []string    `json:"seeds"`
	Maintainers  Maintainers `json:"maintainers"`
}

func (b Body) check() error {
	switch {
	case b.Serial == 0:
		return errors.New("serial must be at least 1")
	case b.Issued.IsZero() || !b.Expires.After(b.Issued):
		return errors.New("expires must be after issued")
	case b.Expires.Sub(b.Issued) > MaxLifetime:
		return fmt.Errorf("valid for %s, at most %s is allowed", b.Expires.Sub(b.Issued), MaxLifetime)
	case b.MaxRatePPS < 1 || b.MaxRatePPS > policy.MaxRate:
		return fmt.Errorf("max_rate_pps %d: want 1 to %d", b.MaxRatePPS, policy.MaxRate)
	case b.MinRescan <= 0 || b.BumpInterval < 0:
		return errors.New("min_rescan must be positive and bump_interval not negative")
	}
	if c, err := hex.DecodeString(b.Catalog); err != nil || len(c) != sha256.Size {
		return fmt.Errorf("catalog %q: want a sha256 in hex", b.Catalog)
	}
	if b.MinVersion != "" {
		if _, ok := parseVersion(b.MinVersion); !ok {
			return fmt.Errorf("min_version %q: want vMAJOR.MINOR.PATCH", b.MinVersion)
		}
	}
	for _, r := range b.RevokedNodes {
		if _, err := sig.DecodeID(r.ID); err != nil {
			return fmt.Errorf("revoked node %q: %w", r.ID, err)
		}
	}
	for _, s := range b.Seeds {
		if s == "" || len(s) > 256 || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) >= 0 {
			return fmt.Errorf("seed %q: want a URL or DNS name", s)
		}
	}
	return b.Maintainers.check()
}

type PauseBody struct {
	Serial  uint64    `json:"serial"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}

type Signature struct {
	Key string `json:"key"`
	Sig []byte `json:"sig"`
}

// Document is a signed policy or emergency pause, as maintainers write it and
// boids relay it. Signatures cover the canonical form of the body.
type Document struct {
	Policy     json.RawMessage `json:"policy,omitempty"`
	Pause      json.RawMessage `json:"emergency_pause,omitempty"`
	Signatures []Signature     `json:"signatures"`
}

func (d Document) message() []byte {
	if d.Policy != nil {
		return sig.JSONMessage(policyTag, d.Policy)
	}
	return sig.JSONMessage(pauseTag, d.Pause)
}

// Sign adds k's signature, replacing an earlier one by the same key.
func (d *Document) Sign(k Signer) {
	d.Signatures = slices.DeleteFunc(d.Signatures, func(s Signature) bool { return s.Key == k.ID() })
	d.Signatures = append(d.Signatures, Signature{Key: k.ID(), Sig: k.Sign(d.message())})
}

// DropInvalid removes signatures that do not match the body, such as those
// made before an edit, and returns their keys.
func (d *Document) DropInvalid() []string {
	var dropped []string
	msg := d.message()
	d.Signatures = slices.DeleteFunc(d.Signatures, func(s Signature) bool {
		if sig.Verify(s.Key, msg, s.Sig) {
			return false
		}
		dropped = append(dropped, s.Key)
		return true
	})
	return dropped
}

// SignedBy lists the keys of set with a valid signature on d.
func (d Document) SignedBy(set Maintainers) []string {
	msg := d.message()
	var out []string
	for _, s := range d.Signatures {
		if slices.Contains(set.Keys, s.Key) && !slices.Contains(out, s.Key) && sig.Verify(s.Key, msg, s.Sig) {
			out = append(out, s.Key)
		}
	}
	return out
}

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

type Policy struct {
	Body
	Doc Document
}

// Parse checks the content of a policy, not its signatures.
func Parse(d Document) (Policy, error) {
	if d.Policy == nil || d.Pause != nil {
		return Policy{}, errors.New("not a policy document")
	}
	var p Policy
	if err := decodeStrict(d.Policy, &p.Body); err != nil {
		return p, fmt.Errorf("policy: %w", err)
	}
	if err := p.check(); err != nil {
		return p, fmt.Errorf("policy %d: %w", p.Serial, err)
	}
	p.Doc = d
	return p, nil
}

func (p *Policy) Revoked(id string) bool {
	return p != nil && slices.ContainsFunc(p.RevokedNodes, func(r Revoked) bool { return r.ID == id })
}

func (p *Policy) RevokedIDs() []string {
	if p == nil {
		return nil
	}
	ids := []string{}
	for _, r := range p.RevokedNodes {
		ids = append(ids, r.ID)
	}
	return ids
}

type Pause struct {
	PauseBody
	Doc Document
}

func ParsePause(d Document) (Pause, error) {
	if d.Pause == nil || d.Policy != nil {
		return Pause{}, errors.New("not an emergency pause document")
	}
	var p Pause
	if err := decodeStrict(d.Pause, &p.PauseBody); err != nil {
		return p, fmt.Errorf("emergency pause: %w", err)
	}
	switch {
	case p.Serial == 0:
		return p, errors.New("emergency pause: serial must be at least 1")
	case p.Issued.IsZero() || !p.Expires.After(p.Issued):
		return p, errors.New("emergency pause: expires must be after issued")
	case p.Expires.Sub(p.Issued) > MaxPause:
		return p, fmt.Errorf("emergency pause: lasts %s, at most %s is allowed", p.Expires.Sub(p.Issued), MaxPause)
	}
	p.Doc = d
	return p, nil
}

// State is what a boid holds: the newest policy, an emergency pause for it,
// and the expiry of every policy it has stored, by serial.
type State struct {
	Latest  *Policy
	Pause   *Pause
	Expires map[uint64]time.Time
}

func (s State) Serial() uint64 {
	if s.Latest == nil {
		return 0
	}
	return s.Latest.Serial
}

// Maintainers is the set that must sign the next policy: the latest policy's,
// or the root before the first one.
func (s State) Maintainers(root Maintainers) Maintainers {
	if s.Latest == nil {
		return root
	}
	return s.Latest.Maintainers
}

// Accept checks that d may follow the current state: a higher serial, signed
// by the threshold of the current maintainers, and of the new ones if the set changes.
func (s State) Accept(root Maintainers, d Document, now time.Time) (Policy, error) {
	p, err := Parse(d)
	if err != nil {
		return p, err
	}
	cur := s.Maintainers(root)
	if err := cur.check(); err != nil {
		return p, fmt.Errorf("no trust root: %w", err)
	}
	if p.Serial <= s.Serial() {
		return p, fmt.Errorf("policy %d: %w (%d)", p.Serial, ErrNotNewer, s.Serial())
	}
	if p.Issued.After(now.Add(maxClockSkew)) {
		return p, fmt.Errorf("policy %d is issued in the future (%s)", p.Serial, p.Issued)
	}
	if n := len(d.SignedBy(cur)); n < cur.Threshold {
		return p, fmt.Errorf("policy %d is signed by %d maintainers, %d needed", p.Serial, n, cur.Threshold)
	}
	if !p.Maintainers.Equal(cur) {
		if n := len(d.SignedBy(p.Maintainers)); n < p.Maintainers.Threshold {
			return p, fmt.Errorf("policy %d changes the maintainers but is signed by %d of the new set, %d needed", p.Serial, n, p.Maintainers.Threshold)
		}
	}
	return p, nil
}

// AcceptPause checks an emergency pause: for the policy in force, signed by
// one of its maintainers, and the first one for that policy.
func (s State) AcceptPause(d Document, now time.Time) (Pause, error) {
	p, err := ParsePause(d)
	if err != nil {
		return p, err
	}
	switch {
	case s.Latest == nil || p.Serial < s.Latest.Serial:
		return p, fmt.Errorf("emergency pause for policy %d: %w", p.Serial, ErrNotNewer)
	case p.Serial > s.Latest.Serial:
		return p, fmt.Errorf("emergency pause for policy %d, which this boid does not have", p.Serial)
	case s.Pause != nil && s.Pause.Serial == p.Serial:
		return p, fmt.Errorf("emergency pause for policy %d: %w: one pause per policy", p.Serial, ErrNotNewer)
	case p.Issued.After(now.Add(maxClockSkew)):
		return p, fmt.Errorf("emergency pause is issued in the future (%s)", p.Issued)
	case len(d.SignedBy(s.Latest.Maintainers)) == 0:
		return p, errors.New("emergency pause is not signed by a maintainer")
	}
	return p, nil
}

func (s State) Paused(now time.Time) bool {
	return s.Pause != nil && s.Latest != nil && s.Pause.Serial == s.Latest.Serial && now.Before(s.Pause.Expires)
}

// Halt explains why this boid must not sweep or grant leases, or returns "".
func (s State) Halt(now time.Time, version, catalogHash, self string) string {
	p := s.Latest
	switch {
	case p == nil:
		return "no flock policy"
	case !now.Before(p.Expires):
		return fmt.Sprintf("flock policy %d expired at %s", p.Serial, sig.Time(p.Expires))
	case p.Pause:
		return fmt.Sprintf("flock policy %d pauses the flock", p.Serial)
	case s.Paused(now):
		return "emergency pause until " + sig.Time(s.Pause.Expires)
	case p.Revoked(self):
		return fmt.Sprintf("flock policy %d revokes this boid", p.Serial)
	case !VersionAtLeast(version, p.MinVersion):
		return fmt.Sprintf("version %s is older than the minimum %s", version, p.MinVersion)
	case catalogHash != p.Catalog:
		return fmt.Sprintf("this boid's catalog %s differs from the policy's %s", sig.Short(catalogHash), sig.Short(p.Catalog))
	}
	return ""
}

// Trusts reports whether a peer may share work and data with this boid: not
// revoked, recent enough, and holding this boid's policy or one that has not expired.
func (s State) Trusts(id, version string, serial uint64, now time.Time) bool {
	if s.Latest.Revoked(id) || (s.Latest != nil && !VersionAtLeast(version, s.Latest.MinVersion)) {
		return false
	}
	if serial == s.Serial() {
		return true
	}
	exp, ok := s.Expires[serial]
	return ok && now.Before(exp)
}

// VersionAtLeast compares the numeric part of vMAJOR.MINOR.PATCH versions;
// anything that does not parse, such as "dev", is older than every minimum.
func VersionAtLeast(version, minimum string) bool {
	if minimum == "" {
		return true
	}
	v, ok1 := parseVersion(version)
	m, ok2 := parseVersion(minimum)
	return ok1 && ok2 && slices.Compare(v[:], m[:]) >= 0
}

func parseVersion(s string) ([3]int, bool) {
	var out [3]int
	s, ok := strings.CutPrefix(s, "v")
	if !ok {
		return out, false
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Bundle is how policies travel: the policies a boid needs to reach the
// newest, oldest first, and an emergency pause for the newest.
type Bundle struct {
	Chain []Document `json:"chain"`
	Pause *Document  `json:"emergency_pause,omitempty"`
}

// Chain picks from stored policies, oldest first, what a boid holding serial
// after needs: every policy that changed the maintainers, and the newest.
func Chain(stored []Policy, after uint64) []Document {
	out := []Document{}
	for i, p := range stored {
		if p.Serial <= after {
			continue
		}
		if i == len(stored)-1 || i == 0 || !p.Maintainers.Equal(stored[i-1].Maintainers) {
			out = append(out, p.Doc)
		}
	}
	return out
}

type Store interface {
	PolicyState(ctx context.Context) (State, error)
	// AddPolicy stores p unless a policy with the same or a higher serial exists.
	AddPolicy(ctx context.Context, p Policy) (bool, error)
	// AddPause stores p unless a pause for its serial exists.
	AddPause(ctx context.Context, p Pause) (bool, error)
	// SyncRevoked marks the peers in ids revoked, deletes their opt-outs and what they
	// reported that no check confirmed, apart from self's own data, and lets
	// peers that are no longer revoked be verified again.
	SyncRevoked(ctx context.Context, ids []string, self string) error
}

// Adopt stores whatever in b is newer than what st holds and returns the new
// state. It skips policies the boid already has, as a bundle from the policy
// URL starts at policy 1, and stops the chain at the first document it rejects.
func Adopt(ctx context.Context, st Store, root Maintainers, self string, b Bundle, now time.Time) (State, bool, error) {
	s, err := st.PolicyState(ctx)
	if err != nil {
		return s, false, err
	}
	changed := false
	var errs []error
	var stale error
	for _, d := range b.Chain {
		p, err := s.Accept(root, d, now)
		if errors.Is(err, ErrNotNewer) {
			stale = err
			continue
		}
		if err != nil {
			errs = append(errs, err)
			break
		}
		ok, err := st.AddPolicy(ctx, p)
		if err != nil {
			return s, changed, err
		}
		if !ok {
			stale = fmt.Errorf("policy %d: %w", p.Serial, ErrNotNewer)
			continue
		}
		changed = true
		s.Latest = &p
		if s.Expires == nil {
			s.Expires = map[uint64]time.Time{}
		}
		s.Expires[p.Serial] = p.Expires
	}
	if changed {
		if err := st.SyncRevoked(ctx, s.Latest.RevokedIDs(), self); err != nil {
			return s, changed, err
		}
	}
	if b.Pause != nil {
		if p, err := s.AcceptPause(*b.Pause, now); err != nil {
			errs = append(errs, err)
		} else if ok, err := st.AddPause(ctx, p); err != nil {
			return s, changed, err
		} else if ok {
			changed = true
			s.Pause = &p
		}
	}
	if !changed && stale != nil {
		errs = append(errs, stale)
	}
	return s, changed, errors.Join(errs...)
}

// Package policy enforces the scanning rules every boidscan node must follow.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/boidscan/boidscan/internal/netset"
)

// MaxRate is the packets-per-second ceiling. Operators may configure less, never more.
const MaxRate = 10000

// Version is set at build time with -ldflags "-X github.com/boidscan/boidscan/internal/policy.Version=...".
var Version = "dev"

type Identity struct {
	ProjectURL   string
	AbuseContact string
}

func (id Identity) Validate() error {
	if !strings.HasPrefix(id.ProjectURL, "http://") && !strings.HasPrefix(id.ProjectURL, "https://") {
		return errors.New("project URL must be an http(s) URL so scanned hosts can find out who is scanning them")
	}
	if strings.TrimSpace(id.AbuseContact) == "" {
		return errors.New("an abuse contact is required")
	}
	return nil
}

func (id Identity) UserAgent() string {
	return fmt.Sprintf("boidscan/%s (+%s; abuse: %s)", Version, id.ProjectURL, id.AbuseContact)
}

type Policy struct {
	Identity
	Rate         int
	AllowPrivate bool
	exclude      *netset.Set
}

func New(id Identity, rate int, allowPrivate bool, optouts ...*netset.Set) (*Policy, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if rate <= 0 {
		rate = MaxRate
	}
	if rate > MaxRate {
		return nil, fmt.Errorf("rate %d exceeds the ceiling of %d packets/s", rate, MaxRate)
	}
	ex := netset.Reserved(allowPrivate)
	for _, o := range optouts {
		if o != nil {
			ex.AddSet(o)
		}
	}
	return &Policy{Identity: id, Rate: rate, AllowPrivate: allowPrivate, exclude: ex}, nil
}

func (p *Policy) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && !p.exclude.Contains(a)
}

// CheckTargets rejects target lists that conflict with the policy. Lab mode only
// lifts the RFC 1918 exclusion, so it is limited to private targets.
func (p *Policy) CheckTargets(targets []netip.Prefix) error {
	if len(targets) == 0 {
		return errors.New("no targets")
	}
	for _, t := range targets {
		if !t.Addr().Is4() {
			return fmt.Errorf("%s: only IPv4 is supported", t)
		}
		if p.AllowPrivate && !netset.IsPrivate(t) {
			return fmt.Errorf("%s: lab mode only scans RFC 1918 ranges", t)
		}
	}
	return nil
}

// WriteBlocklist writes the exclusion set to a temp file for zmap and zgrab2.
// The caller removes the file.
func (p *Policy) WriteBlocklist() (string, error) {
	f, err := os.CreateTemp("", "boidscan-blocklist-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := p.exclude.Write(f); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

// Package fed lets boids find each other (signed node records, seeds,
// endpoint challenges, gossip and liveness) and share work and results
// (block placement, replication, leases and the sweep).
package fed

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"time"
	"unicode"

	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/pkg/sig"
)

// Record is what a boid says about itself. It is signed by its own key, so it
// can be passed on by others without being altered.
type Record struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	Contact    string `json:"contact"`
	ProjectURL string `json:"project_url"`
	Version    string `json:"version"`
	// Catalog is the hash of the work catalog; boids share work only with equal catalogs.
	Catalog string `json:"catalog"`
	// Root names the first maintainer set; boids with different roots are different flocks.
	Root           string    `json:"root"`
	PolicySerial   uint64    `json:"policy_serial"`
	EmergencyPause bool      `json:"emergency_pause,omitempty"`
	Time           time.Time `json:"time"`
	Signature      []byte    `json:"signature"`
}

type Signer interface {
	ID() string
	Sign([]byte) []byte
}

func (r Record) message() []byte {
	return sig.Message("boidscan-node-v2", r.ID, r.Name, r.Endpoint, r.Contact, r.ProjectURL, r.Version, r.Catalog,
		r.Root, strconv.FormatUint(r.PolicySerial, 10), strconv.FormatBool(r.EmergencyPause), sig.Time(r.Time))
}

func (r *Record) sign(k Signer) {
	r.ID = k.ID()
	r.Time = r.Time.UTC().Truncate(time.Microsecond)
	r.Signature = k.Sign(r.message())
}

// Label is how a peer appears in logs: its self-chosen name plus the start of
// its ID, since names are not unique.
func (r Record) Label() string {
	return r.Name + " (" + sig.Short(r.ID) + ")"
}

func (r Record) verify() error {
	for field, v := range map[string]string{"name": r.Name, "endpoint": r.Endpoint, "contact": r.Contact, "project_url": r.ProjectURL, "version": r.Version, "catalog": r.Catalog, "root": r.Root} {
		if len(v) > 256 {
			return fmt.Errorf("%s is too long", field)
		}
		for _, c := range v {
			if !unicode.IsPrint(c) {
				return fmt.Errorf("%s contains control characters", field)
			}
		}
	}
	if r.Name == "" || len(r.Name) > 32 {
		return errors.New("name must be 1 to 32 characters")
	}
	if !sig.Verify(r.ID, r.message(), r.Signature) {
		return errors.New("signature does not match")
	}
	return nil
}

// checkEndpoint requires a plain http://IPv4 URL: scanned hosts look for the
// info page on port 80 of the scanning address, so that is where a boid lives.
func checkEndpoint(endpoint string, allowPrivate bool) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Port() != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("endpoint %q: want http://<IPv4 address>", endpoint)
	}
	ip, err := netip.ParseAddr(u.Host)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("endpoint %q: want http://<IPv4 address>", endpoint)
	}
	if netset.Reserved(allowPrivate).Contains(ip) {
		return fmt.Errorf("endpoint %q: reserved address", endpoint)
	}
	return nil
}

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/boidscan/boidscan/internal/grab"
)

var fingerprintField = regexp.MustCompile(`"fingerprint_sha256":"[0-9a-fA-F]+"`)

// forge is what a lying boid would report, for the lab: every certificate and
// host key replaced, and a copy of each service at the next address, where
// nothing listens.
func forge(o grab.Observation) []grab.Observation {
	if o.Status != "success" {
		return []grab.Observation{o}
	}
	fake := sha256.Sum256(append([]byte("forged"), o.Raw...))
	o.Raw = fingerprintField.ReplaceAll(o.Raw, []byte(`"fingerprint_sha256":"`+hex.EncodeToString(fake[:])+`"`))
	phantom := o
	phantom.IP = o.IP.Next()
	return []grab.Observation{o, phantom}
}

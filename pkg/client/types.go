package client

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/boidscan/boidscan/pkg/sig"
)

// Observation is one zgrab2 module result for one ip:port, as seen by one node.
type Observation struct {
	ID       int64  `json:"id"`
	RunID    int64  `json:"run_id"`
	NodeID   string `json:"node_id"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	// FirstSeenAt is when this node first saw the service as it is now; SeenAt
	// is the last time, and the time Signature covers.
	FirstSeenAt time.Time       `json:"first_seen_at"`
	SeenAt      time.Time       `json:"seen_at"`
	CertSHA256  string          `json:"cert_sha256,omitempty"`
	CertNames   []string        `json:"cert_names,omitempty"`
	Data        json.RawMessage `json:"data"`
	// Signature is NodeID's Ed25519 signature; see Verify.
	Signature []byte `json:"signature,omitempty"`
	// Seq orders a node's rows for replication; it is not sent.
	Seq int64 `json:"-"`
}

// Verify checks that NodeID signed this observation.
func (o Observation) Verify() error {
	if len(o.Signature) == 0 {
		return errors.New("observation is not signed")
	}
	if !sig.Verify(o.NodeID, sig.ObservationMessage(o.IP, o.Port, o.Name, o.Protocol, o.Status, o.SeenAt, o.Data), o.Signature) {
		return errors.New("observation signature does not match")
	}
	return nil
}

type Host struct {
	IP       string        `json:"ip"`
	Services []Observation `json:"services"`
}

// Query selects observations. Empty fields are not filtered on.
type Query struct {
	CIDR string
	Port int
	// Text is a case-insensitive substring match on the raw result.
	Text string
	// Cert matches a certificate SHA-256 fingerprint or a subject alternative name.
	Cert string
	// Before returns observations with an ID lower than this, for paging.
	Before int64
	Limit  int
}

type Page struct {
	Results []Observation `json:"results"`
	// Next is passed as Query.Before to fetch the next page. Zero means no more results.
	Next int64 `json:"next"`
}

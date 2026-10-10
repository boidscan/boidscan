// Package sig holds the node ID encoding and the signed message formats that
// let anyone check which node produced a record.
package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeID turns a public key into a node ID: lowercase unpadded base32.
func EncodeID(pub ed25519.PublicKey) string {
	return strings.ToLower(idEncoding.EncodeToString(pub))
}

func DecodeID(id string) (ed25519.PublicKey, error) {
	b, err := idEncoding.DecodeString(strings.ToUpper(id))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid node id")
	}
	return ed25519.PublicKey(b), nil
}

// Short is the prefix of a node ID used in logs and on the info page.
func Short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func Verify(id string, msg, signature []byte) bool {
	pub, err := DecodeID(id)
	return err == nil && ed25519.Verify(pub, msg, signature)
}

// Time is the canonical timestamp form. Postgres keeps microseconds, so
// anything finer would not survive a round trip.
func Time(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

// Message joins a domain tag and fields, one per line. Fields must not contain newlines.
func Message(tag string, fields ...string) []byte {
	return []byte(tag + "\n" + strings.Join(fields, "\n"))
}

func ObservationMessage(ip string, port int, name, protocol, status string, seenAt time.Time, raw []byte) []byte {
	sum := sha256.Sum256(canonicalJSON(raw))
	return Message("boidscan-observation-v1", ip, strconv.Itoa(port), name, protocol, status, Time(seenAt), hex.EncodeToString(sum[:]))
}

// canonicalJSON is the form encoding/json emits for a json.RawMessage, so a
// result re-encoded by an API response still hashes the same.
func canonicalJSON(raw []byte) []byte {
	var compact, out bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return raw
	}
	json.HTMLEscape(&out, compact.Bytes())
	return out.Bytes()
}

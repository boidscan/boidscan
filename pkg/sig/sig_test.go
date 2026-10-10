package sig

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestIDRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	id := EncodeID(pub)
	got, err := DecodeID(id)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("DecodeID(%q) = %v, %v", id, got, err)
	}
	for _, bad := range []string{"", "abc", id[:len(id)-1], id + "a"} {
		if _, err := DecodeID(bad); err == nil {
			t.Errorf("DecodeID(%q) accepted", bad)
		}
	}
}

func TestObservationMessage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := EncodeID(pub)
	seen := time.Date(2026, 10, 10, 18, 42, 41, 123456789, time.FixedZone("x", 3600))
	raw := []byte(`{"banner": "<b>&"}`)
	s := ed25519.Sign(priv, ObservationMessage("192.0.2.1", 22, "ssh22", "ssh", "success", seen, raw))

	// The same result as an API response re-encodes it: compact, HTML-escaped, microseconds.
	reencoded := []byte(`{"banner":"<b>&"}`)
	if !Verify(id, ObservationMessage("192.0.2.1", 22, "ssh22", "ssh", "success", seen.UTC().Truncate(time.Microsecond), reencoded), s) {
		t.Fatal("re-encoded observation does not verify")
	}
	if Verify(id, ObservationMessage("192.0.2.1", 23, "ssh22", "ssh", "success", seen, raw), s) {
		t.Fatal("tampered port verified")
	}
	if Verify(id, ObservationMessage("192.0.2.1", 22, "ssh22", "ssh", "success", seen, []byte(`{"banner":"x"}`)), s) {
		t.Fatal("tampered data verified")
	}
}

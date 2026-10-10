package netset

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestReadContains(t *testing.T) {
	s, err := Read(strings.NewReader("# comment\n198.51.100.0/24\n\n203.0.113.7 # single host\n"))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"198.51.100.1":          true,
		"203.0.113.7":           true,
		"203.0.113.8":           false,
		"::ffff:198.51.100.200": true,
		"8.8.8.8":               false,
	} {
		if got := s.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestReadRejectsGarbage(t *testing.T) {
	if _, err := Read(strings.NewReader("not-an-ip\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestReserved(t *testing.T) {
	strict := Reserved(false)
	lab := Reserved(true)
	if !strict.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("strict set must contain RFC1918")
	}
	if lab.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("lab set must not contain RFC1918")
	}
	for _, s := range []*Set{strict, lab} {
		if !s.Contains(netip.MustParseAddr("127.0.0.1")) || !s.Contains(netip.MustParseAddr("239.1.1.1")) {
			t.Error("loopback and multicast must always be reserved")
		}
	}
}

func TestOverlaps(t *testing.T) {
	s := &Set{}
	s.Add(netip.MustParsePrefix("198.51.100.0/25"))
	if !s.Overlaps(netip.MustParsePrefix("198.51.100.0/24")) {
		t.Error("expected overlap with covering prefix")
	}
	if s.Overlaps(netip.MustParsePrefix("198.51.100.128/25")) {
		t.Error("unexpected overlap")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	s := Reserved(false)
	var buf bytes.Buffer
	if err := s.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != s.Len() {
		t.Fatalf("round trip lost prefixes: %d != %d", r.Len(), s.Len())
	}
}

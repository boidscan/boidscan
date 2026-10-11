package policy

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/boidscan/boidscan/internal/netset"
)

var id = Identity{ProjectURL: "https://boidscan.example", AbuseContact: "abuse@boidscan.example"}

func TestRateCeiling(t *testing.T) {
	if _, err := New(id, MaxRate+1, false); err == nil {
		t.Fatal("rate above ceiling must be rejected")
	}
	p, err := New(id, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rate != MaxRate {
		t.Fatalf("default rate = %d, want %d", p.Rate, MaxRate)
	}
	p, err = New(id, 100, false)
	if err != nil || p.Rate != 100 {
		t.Fatalf("lower rate must be accepted, got %v %v", p, err)
	}
}

func TestIdentityRequired(t *testing.T) {
	for _, bad := range []Identity{
		{},
		{ProjectURL: "boidscan.example", AbuseContact: "x"},
		{ProjectURL: "https://boidscan.example"},
		{ProjectURL: "https://boidscan.example", AbuseContact: "you@example.org"},
		{ProjectURL: "https://boidscan.example", AbuseContact: "Abuse@Mail.Example.COM"},
	} {
		if _, err := New(bad, 0, false); err == nil {
			t.Errorf("identity %+v must be rejected", bad)
		}
	}
	if ua := id.UserAgent(); !strings.Contains(ua, id.ProjectURL) || !strings.Contains(ua, id.AbuseContact) {
		t.Errorf("user agent %q must name project and contact", ua)
	}
}

func TestExclusionsAndReserved(t *testing.T) {
	opt, _ := netset.Read(strings.NewReader("198.51.100.0/24\n"))
	p, err := New(id, 0, false, opt)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"198.51.100.9": false,
		"10.0.0.1":     false,
		"127.0.0.1":    false,
		"1.1.1.1":      true,
		"2001:db8::1":  false,
	} {
		if got := p.Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestLabMode(t *testing.T) {
	opt, _ := netset.Read(strings.NewReader("10.9.0.0/16\n"))
	p, err := New(id, 0, true, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(netip.MustParseAddr("10.1.0.5")) {
		t.Error("lab mode must allow RFC1918")
	}
	if p.Allowed(netip.MustParseAddr("10.9.0.5")) {
		t.Error("exclusions must still apply in lab mode")
	}
	if p.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("loopback must stay excluded in lab mode")
	}
	if err := p.CheckTargets([]netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}); err == nil {
		t.Error("lab mode must refuse public targets")
	}
	if err := p.CheckTargets([]netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")}); err != nil {
		t.Error(err)
	}
}

func TestWriteBlocklist(t *testing.T) {
	opt, _ := netset.Read(strings.NewReader("198.51.100.0/24\n"))
	p, _ := New(id, 0, false, opt)
	path, err := p.WriteBlocklist()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "198.51.100.0/24") || !strings.Contains(string(b), "10.0.0.0/8") {
		t.Fatalf("blocklist missing entries:\n%s", b)
	}
}

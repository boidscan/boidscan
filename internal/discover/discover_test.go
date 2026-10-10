package discover

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/boidscan/boidscan/internal/netset"
	"github.com/boidscan/boidscan/internal/policy"
)

func testPolicy(t *testing.T, optout string) *policy.Policy {
	t.Helper()
	opt, err := netset.Read(strings.NewReader(optout))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.New(policy.Identity{ProjectURL: "https://boidscan.example", AbuseContact: "abuse@boidscan.example"}, 500, false, opt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestArgs(t *testing.T) {
	args := Args(Options{
		Targets:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Ports:     []uint16{22, 443},
		Blocklist: "/tmp/bl",
		Rate:      500,
	})
	for _, want := range []string{"--target-ports=22,443", "--rate=500", "--blocklist-file=/tmp/bl", "192.0.2.0/24"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
}

func TestParseFilters(t *testing.T) {
	o := Options{
		Targets: []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16"), netip.MustParsePrefix("198.51.100.0/24")},
		Ports:   []uint16{80, 443},
	}
	p := testPolicy(t, "1.1.9.0/24\n")
	input := "saddr,sport\n" +
		"1.1.1.1,80\n" +
		"1.1.1.2,8080\n" + // port not requested
		"1.1.9.9,443\n" + // opted out
		"8.8.8.8,443\n" + // outside targets
		"198.51.100.4,443\n" + // reserved documentation range
		"1.1.2.2,443\n"
	out := make(chan Hit, 10)
	if err := Parse(strings.NewReader(input), o, p, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var got []Hit
	for h := range out {
		got = append(got, h)
	}
	want := []Hit{
		{netip.MustParseAddr("1.1.1.1"), 80},
		{netip.MustParseAddr("1.1.2.2"), 443},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	o := Options{Targets: []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}, Ports: []uint16{80}}
	out := make(chan Hit, 1)
	if err := Parse(strings.NewReader("garbage\n"), o, testPolicy(t, ""), out); err == nil {
		t.Fatal("expected error")
	}
}

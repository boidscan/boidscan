package scan

import (
	"net/netip"
	"testing"

	"github.com/boidscan/boidscan/internal/grab"
)

func TestForge(t *testing.T) {
	o := grab.Observation{IP: netip.MustParseAddr("172.30.0.10"), Port: 443, Name: "https443", Status: "success",
		Raw: []byte(`{"server_certificates":{"certificate":{"parsed":{"fingerprint_sha256":"aa11"}}}}`)}
	out := forge(o)
	if len(out) != 2 || out[1].IP != netip.MustParseAddr("172.30.0.11") {
		t.Fatalf("forge = %+v, want the result and a phantom at the next address", out)
	}
	if fp := grab.Fingerprint(out[0].Raw); fp == "" || fp == "aa11" {
		t.Fatalf("fingerprint %q was not replaced", fp)
	}
	if failed := (grab.Observation{Status: "io-timeout"}); len(forge(failed)) != 1 {
		t.Fatal("a failed grab must be left alone")
	}
}

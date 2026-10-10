package main

import (
	"testing"

	"github.com/boidscan/boidscan/internal/grab"
)

func TestParsePorts(t *testing.T) {
	known := grab.DefaultServices("ua")
	all, err := parsePorts("", known)
	if err != nil || len(all) != len(known) {
		t.Fatalf("empty selection must return all services, got %d, %v", len(all), err)
	}
	sel, err := parsePorts("22, 443", known)
	if err != nil || len(sel) != 2 || sel[0].Name != "ssh22" || sel[1].Name != "https443" {
		t.Fatalf("got %+v, %v", sel, err)
	}
	for _, bad := range []string{"9999", "abc", "70000"} {
		if _, err := parsePorts(bad, known); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("BOIDSCAN_LISTEN", ":9000")
	if got := env("LISTEN", ":80"); got != ":9000" {
		t.Errorf("env = %q", got)
	}
	if got := env("UNSET_FOR_TEST", "fallback"); got != "fallback" {
		t.Errorf("env fallback = %q", got)
	}
}

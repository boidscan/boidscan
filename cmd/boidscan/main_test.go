package main

import (
	"slices"
	"testing"

	"github.com/boidscan/boidscan/internal/grab"
)

func TestParsePorts(t *testing.T) {
	all, err := parsePorts("")
	if err != nil || len(all) != len(grab.DefaultPorts()) {
		t.Fatalf("empty selection must return the default ports, got %d, %v", len(all), err)
	}
	sel, err := parsePorts("587, 8000-8002,22,8001")
	if err != nil || !slices.Equal(sel, []uint16{587, 8000, 8001, 8002, 22}) {
		t.Fatalf("got %v, %v", sel, err)
	}
	for _, bad := range []string{"abc", "70000", "0", "90-80", "1-"} {
		if _, err := parsePorts(bad); err == nil {
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

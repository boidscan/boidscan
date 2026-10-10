package grab

import (
	"strings"
	"testing"
)

func TestINI(t *testing.T) {
	ini := INI(NewPlan("boidscan/test", []uint16{22, 443, 9999}).Services())
	for _, want := range []string{
		"[http]\ntrigger=\"https443\"\nname=\"https443\"\nport=443\nraw-headers=\"true\"\nuse-https=\"true\"\nuser-agent=\"boidscan/test\"\n",
		"[ssh]\ntrigger=\"ssh22\"\nname=\"ssh22\"\nport=22\n",
		"[banner]\ntrigger=\"banner\"\nname=\"banner\"\n\n",
		"retry-https=\"true\"\n",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("INI missing section:\n%s\ngot:\n%s", want, ini)
		}
	}
}

func TestServicesUnique(t *testing.T) {
	names, ports := map[string]bool{}, map[uint16]bool{}
	for _, s := range append(KnownServices("x"), GenericServices("x")...) {
		if names[s.Name] || (!s.Generic && ports[s.Port]) {
			t.Fatalf("duplicate service %+v", s)
		}
		names[s.Name] = true
		if !s.Generic {
			ports[s.Port] = true
		}
	}
}

func TestParseLine(t *testing.T) {
	byName := map[string]Service{}
	for _, s := range KnownServices("x") {
		byName[s.Name] = s
	}
	line := `{"ip":"192.0.2.10","data":{"ssh22":{"status":"success","protocol":"ssh","port":22,"result":{"server_id":{"raw":"SSH-2.0-OpenSSH_9.6"}},"timestamp":"2026-10-10T10:00:00Z"},"unknown":{"status":"success"}}}`
	obs, err := ParseLine([]byte(line), byName)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	o := obs[0]
	if o.IP.String() != "192.0.2.10" || o.Port != 22 || o.Name != "ssh22" || o.Protocol != "ssh" || o.Status != "success" {
		t.Fatalf("unexpected observation %+v", o)
	}
	if !strings.Contains(string(o.Raw), "OpenSSH_9.6") {
		t.Fatal("raw response not preserved")
	}
}

func TestParseLinePortFallback(t *testing.T) {
	byName := map[string]Service{"http80": {Name: "http80", Module: "http", Port: 80}}
	obs, err := ParseLine([]byte(`{"ip":"192.0.2.1","data":{"http80":{"status":"io-timeout","protocol":"http"}}}`), byName)
	if err != nil || len(obs) != 1 || obs[0].Port != 80 {
		t.Fatalf("got %+v, %v", obs, err)
	}
}

func TestDefaultPortsCoverKnownServices(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) < 1000 {
		t.Fatalf("only %d default ports", len(ports))
	}
	have := map[uint16]bool{}
	for _, p := range ports {
		have[p] = true
	}
	for _, s := range KnownServices("x") {
		if !have[s.Port] {
			t.Errorf("default ports miss %d (%s)", s.Port, s.Name)
		}
	}
}

func TestPlan(t *testing.T) {
	plan := NewPlan("x", []uint16{22, 587, 9443})
	if s := plan.For(587); len(s) != 1 || s[0].Name != "smtp587" {
		t.Errorf("587 -> %+v", s)
	}
	if s := plan.For(9443); len(s) != 2 || !s[0].Generic || !s[1].Generic {
		t.Errorf("9443 -> %+v", s)
	}
	if n := len(NewPlan("x", []uint16{22, 443}).Services()); n != 2 {
		t.Errorf("known ports only: %d services, want 2 without generic", n)
	}
}

func TestParseLineGeneric(t *testing.T) {
	byName := map[string]Service{}
	for _, s := range GenericServices("x") {
		byName[s.Name] = s
	}
	ok := `{"ip":"192.0.2.1","data":{"banner":{"status":"success","protocol":"banner","port":2200,"result":{"banner":"SSH-2.0-x"}}}}`
	obs, err := ParseLine([]byte(ok), byName)
	if err != nil || len(obs) != 1 || obs[0].Port != 2200 || obs[0].Name != "banner" {
		t.Fatalf("got %+v, %v", obs, err)
	}
	failed := `{"ip":"192.0.2.1","data":{"http":{"status":"unknown-error","protocol":"http","port":2200}}}`
	if obs, err := ParseLine([]byte(failed), byName); err != nil || len(obs) != 0 {
		t.Fatalf("failed generic result must be dropped, got %+v, %v", obs, err)
	}
}

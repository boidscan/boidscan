package grab

import (
	"strings"
	"testing"
)

func TestINI(t *testing.T) {
	ini := INI(DefaultServices("boidscan/test"))
	for _, want := range []string{
		"[http]\ntrigger=\"https443\"\nname=\"https443\"\nport=443\nraw-headers=\"true\"\nuse-https=\"true\"\nuser-agent=\"boidscan/test\"\n",
		"[ssh]\ntrigger=\"ssh22\"\nname=\"ssh22\"\nport=22\n",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("INI missing section:\n%s\ngot:\n%s", want, ini)
		}
	}
}

func TestDefaultServicesUnique(t *testing.T) {
	names, ports := map[string]bool{}, map[uint16]bool{}
	for _, s := range DefaultServices("x") {
		if names[s.Name] || ports[s.Port] {
			t.Fatalf("duplicate service %+v", s)
		}
		names[s.Name], ports[s.Port] = true, true
	}
}

func TestParseLine(t *testing.T) {
	byName := map[string]Service{}
	for _, s := range DefaultServices("x") {
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

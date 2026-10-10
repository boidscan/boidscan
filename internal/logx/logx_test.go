package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSetup(t *testing.T) {
	defer slog.SetDefault(slog.Default())
	var console bytes.Buffer
	file := filepath.Join(t.TempDir(), "debug.jsonl")
	closeLog, err := Setup(&console, slog.LevelInfo, file, "boid-a")
	if err != nil {
		t.Fatal(err)
	}
	slog.Debug("gossip round", "peers", 2)
	slog.With("peer", "boid-b").Info("verified peer", "endpoint", "http://192.0.2.5", "note", "two words")
	closeLog()

	want := regexp.MustCompile(`^\d\d:\d\d:\d\d INFO  verified peer peer=boid-b endpoint=http://192.0.2.5 note="two words"\n$`)
	if !want.MatchString(console.String()) {
		t.Errorf("console = %q", console.String())
	}

	b, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("debug file has %d lines, want both records: %s", len(lines), b)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["node"] != "boid-a" || rec["msg"] != "gossip round" || rec["level"] != "DEBUG" {
		t.Errorf("debug record = %v", rec)
	}
}

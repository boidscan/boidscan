package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const stamp = `\d{4}-\d\d-\d\d \d\d:\d\d:\d\d`

func TestSetup(t *testing.T) {
	defer slog.SetDefault(slog.Default())
	var console bytes.Buffer
	file := filepath.Join(t.TempDir(), "debug.jsonl")
	closeLog, err := Setup(&console, slog.LevelInfo, file, "boid-a")
	if err != nil {
		t.Fatal(err)
	}
	slog.Debug("gossip round", "peers", 2)
	slog.With("peer", "boid-b").Info("verified boid-b", "endpoint", "http://192.0.2.5", "note", "two words")
	slog.Warn("could not reach boid-b", "err", errors.New("connection refused"), "peer", "boid-b")
	slog.Log(context.Background(), LevelCritical, "worker failed")
	closeLog()

	want := regexp.MustCompile(`^` + stamp + ` - boid-a: verified boid-b\n` +
		stamp + ` - boid-a \[warning\]: could not reach boid-b: connection refused\n` +
		stamp + ` - boid-a \[critical\]: worker failed\n$`)
	if !want.MatchString(console.String()) {
		t.Errorf("console = %q", console.String())
	}

	b, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 {
		t.Fatalf("debug file has %d lines, want all records: %s", len(lines), b)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["node"] != "boid-a" || rec["msg"] != "gossip round" || rec["level"] != "DEBUG" {
		t.Errorf("debug record = %v", rec)
	}
	if err := json.Unmarshal([]byte(lines[3]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["level"] != "CRITICAL" {
		t.Errorf("critical record = %v", rec)
	}
}

func TestConsoleDebugShowsFields(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewConsole(&buf, slog.LevelDebug, "wren"))
	log.With("peer", "boid-b").Info("verified boid-b", "endpoint", "http://192.0.2.5", "note", "two words")
	log.Debug("gossiped", "sent", 3)
	want := regexp.MustCompile(`^` + stamp + ` - wren: verified boid-b peer=boid-b endpoint=http://192.0.2.5 note="two words"\n` +
		stamp + ` - wren \[debug\]: gossiped sent=3\n$`)
	if !want.MatchString(buf.String()) {
		t.Errorf("console = %q", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"INFO":     slog.LevelInfo,
		"Warning":  slog.LevelWarn,
		"warn":     slog.LevelWarn,
		"ERROR":    slog.LevelError,
		"critical": LevelCritical,
	} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("bogus"); err == nil || !strings.Contains(err.Error(), "CRITICAL") {
		t.Errorf("ParseLevel(bogus) error = %v", err)
	}
}

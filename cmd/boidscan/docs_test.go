package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readAll(t *testing.T, patterns ...string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range patterns {
		files, err := filepath.Glob(p)
		if err != nil || len(files) == 0 {
			t.Fatalf("no files match %s", p)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(data)
		}
	}
	return b.String()
}

func TestConfigurationDocumented(t *testing.T) {
	code := readAll(t, "*.go")
	doc := readAll(t, "../../docs/configuration.md")
	names := regexp.MustCompile(`env(?:Duration)?\("([A-Z0-9_]+)"`).FindAllStringSubmatch(code, -1)
	if len(names) == 0 {
		t.Fatal("found no env() calls")
	}
	for _, m := range names {
		if !strings.Contains(doc, "`BOIDSCAN_"+m[1]+"`") {
			t.Errorf("BOIDSCAN_%s is missing from docs/configuration.md", m[1])
		}
	}
}

func TestRoutesDocumented(t *testing.T) {
	code := readAll(t, "../../internal/api/*.go", "../../internal/fed/*.go")
	doc := readAll(t, "../../docs/api.md")
	routes := regexp.MustCompile(`HandleFunc\("[A-Z]+ (/[a-z][^"]*)"`).FindAllStringSubmatch(code, -1)
	if len(routes) == 0 {
		t.Fatal("found no routes")
	}
	for _, m := range routes {
		if !strings.Contains(doc, m[1]) {
			t.Errorf("%s is missing from docs/api.md", m[1])
		}
	}
}

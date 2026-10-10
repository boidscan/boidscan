package identity

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadCreatesOnceAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "node.key")
	ids := make([]string, 8)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Go(func() {
			k, err := Load(path)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = k.ID()
		})
	}
	wg.Wait()
	for _, id := range ids[1:] {
		if id != ids[0] {
			t.Fatalf("concurrent loads returned different keys: %v", ids)
		}
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v; want 0600", st.Mode(), err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	os.WriteFile(path, []byte("nope"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("garbage key accepted")
	}
}

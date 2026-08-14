package codec

import (
	"os"
	"path/filepath"
	"testing"
)

func protocolFile(t testing.TB, elem ...string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		cand := filepath.Join(append([]string{dir, "testdata", "protocol"}, elem...)...)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("testdata/protocol/%s not found", filepath.Join(elem...))
	return ""
}

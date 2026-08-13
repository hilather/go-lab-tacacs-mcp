package observability

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanariesAbsentFromCheckedInArtifacts(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	skipDir := map[string]struct{}{
		".git": {}, "bin": {}, "web/node_modules": {}, "web/dist": {},
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if _, skip := skipDir[rel]; skip || strings.Contains(rel, "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".md", ".yml", ".yaml", ".json", ".ts", ".tsx", ".js", ".html", ".css", ".txt":
		default:
			return nil
		}
		// This test file and canary.go plant the strings.
		base := filepath.Base(path)
		if base == "canary.go" || strings.HasPrefix(base, "canary_") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if hits := ScanCanaries(string(raw)); len(hits) > 0 {
			t.Errorf("%s", FormatHits(rel, hits))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}

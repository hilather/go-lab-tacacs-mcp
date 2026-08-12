package spike

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionSourcesDoNotImportSpike(t *testing.T) {
	t.Parallel()
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "cmd"),
	}
	needle := "github.com/hilather/go-lab-tacacs-mcp/tools/spike"
	var hits []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), needle) {
				hits = append(hits, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(hits) > 0 {
		t.Fatalf("production sources import tools/spike: %s", strings.Join(hits, ", "))
	}
}

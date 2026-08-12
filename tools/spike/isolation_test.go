package spike

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spikeImportPath = "github.com/hilather/go-lab-tacacs-mcp/tools/spike"

func TestProductionSourcesDoNotImportSpike(t *testing.T) {
	t.Parallel()
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "cmd"),
		filepath.Join("..", "..", "web"),
	}
	var hits []string
	fset := token.NewFileSet()
	for _, root := range roots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "dist", "testdata":
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, spec := range file.Imports {
				if strings.Trim(spec.Path.Value, `"`) == spikeImportPath {
					hits = append(hits, path)
				}
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

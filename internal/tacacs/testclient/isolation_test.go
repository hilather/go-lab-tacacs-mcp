package testclient

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentOfServerCodec(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/legacy",
		"github.com/hilather/go-lab-tacacs-mcp/tools/spike",
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imp := strings.Trim(spec.Path.Value, `"`)
			for _, bad := range forbidden {
				if imp == bad || strings.HasPrefix(imp, bad+"/") {
					t.Errorf("%s imports forbidden package %s", path, imp)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

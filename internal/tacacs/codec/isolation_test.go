package codec

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"github.com/hilather/go-lab-tacacs-mcp/tools/spike",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec",
		"github.com/hilather/go-lab-tacacs-mcp/internal/credentials",
		"github.com/hilather/go-lab-tacacs-mcp/internal/policy",
		"github.com/hilather/go-lab-tacacs-mcp/internal/api",
		"github.com/hilather/go-lab-tacacs-mcp/internal/config",
		"net",
		"net/http",
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
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

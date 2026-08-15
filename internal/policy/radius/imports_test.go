package radius

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"net/http",
		"github.com/hilather/go-lab-tacacs-mcp/internal/aaa",
		"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec",
		"github.com/hilather/go-lab-tacacs-mcp/internal/radius/udp",
		"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server",
		"github.com/hilather/go-lab-tacacs-mcp/internal/api",
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs",
		"github.com/hilather/go-lab-tacacs-mcp/internal/events",
		"gopkg.in/yaml.v3",
	}
	// Exact match only: prefix would also ban this package (internal/policy/radius).
	forbiddenExact := []string{
		"github.com/hilather/go-lab-tacacs-mcp/internal/policy",
	}
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if path == bad || strings.HasPrefix(path, bad+"/") {
						t.Errorf("%s imports forbidden package %s", name, path)
					}
				}
				for _, bad := range forbiddenExact {
					if path == bad {
						t.Errorf("%s imports forbidden package %s", name, path)
					}
				}
			}
		}
	}
}

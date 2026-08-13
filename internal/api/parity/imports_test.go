package parity

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestNoForbiddenProductionImports(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	// Tests may import both adapters. Production files must not grow a
	// second operation layer or speak TACACS.
	forbidden := []string{
		"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs",
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
			}
		}
	}
}

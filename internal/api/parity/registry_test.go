package parity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

func TestRegistryCompleteness(t *testing.T) {
	t.Parallel()
	root, err := operations.FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := registry.ValidateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid() {
		for _, issue := range rep.Issues {
			t.Error(issue.String())
		}
	}

	spec, err := operations.LoadSpec(filepath.Join(root, registry.OperationsPath))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operations.NewFromRepo(root, operations.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	doc := rest.BuildOpenAPI(reg)
	paths, _ := doc["paths"].(map[string]any)
	generated, err := os.ReadFile(filepath.Join(root, registry.GeneratedParity))
	if err != nil {
		t.Fatal(err)
	}
	genText := string(generated)

	seenIDs := map[string]struct{}{}
	seenRoutes := map[string]string{}
	seenTools := map[string]string{}
	for _, op := range spec.Operations {
		if _, dup := seenIDs[op.ID]; dup {
			t.Errorf("duplicate operation id %s", op.ID)
		}
		seenIDs[op.ID] = struct{}{}
		got, ok := reg.Lookup(op.ID)
		if !ok {
			t.Errorf("%s missing from Go registry", op.ID)
			continue
		}
		if got.Parity == "" {
			t.Errorf("%s missing disposition", op.ID)
		}
		needBoth := op.Parity == registry.ParityRequired || op.Parity == registry.ParityDifferentBinding
		if needBoth && (got.REST.Method == "" || got.REST.Path == "") {
			t.Errorf("%s missing REST binding", op.ID)
		}
		if needBoth && got.MCP.Kind == "" {
			t.Errorf("%s missing MCP binding", op.ID)
		}
		if needBoth && len(got.Scopes) == 0 {
			t.Errorf("%s missing scopes", op.ID)
		}
		if got.REST.Path != "" && paths != nil {
			if _, ok := paths[got.REST.Path]; !ok {
				t.Errorf("%s REST path %s missing from OpenAPI", op.ID, got.REST.Path)
			}
		}
		if got.REST.Method != "" && got.REST.Path != "" {
			key := got.REST.Method + " " + got.REST.Path
			if prev, ok := seenRoutes[key]; ok {
				t.Errorf("duplicate REST route %s (%s and %s)", key, prev, op.ID)
			}
			seenRoutes[key] = op.ID
		}
		if got.MCP.Kind == "tool" && got.MCP.Name != "" {
			if prev, ok := seenTools[got.MCP.Name]; ok {
				t.Errorf("duplicate MCP tool %s (%s and %s)", got.MCP.Name, prev, op.ID)
			}
			seenTools[got.MCP.Name] = op.ID
		}
		if !strings.Contains(genText, op.ID) {
			t.Errorf("%s missing from %s", op.ID, registry.GeneratedParity)
		}
		if (op.Parity == registry.ParityRequired || op.Parity == registry.ParityDifferentBinding) && !got.Implemented {
			t.Errorf("%s is %s but not implemented", op.ID, op.Parity)
		}
	}
}

func TestMissingBindingFailsClosed(t *testing.T) {
	t.Parallel()
	spec, err := operations.LoadRepoSpec(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range spec.Operations {
		if op.Parity != registry.ParityRequired {
			continue
		}
		if op.REST.Method == "" || op.REST.Path == "" || op.MCP.Name == "" {
			t.Fatalf("PARITY_REQUIRED %s missing a required binding", op.ID)
		}
	}
}

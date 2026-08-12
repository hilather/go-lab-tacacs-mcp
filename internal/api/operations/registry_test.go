package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

func TestRegistryCompletenessMatchesYAML(t *testing.T) {
	t.Parallel()
	root := mustRoot(t)
	yamlDoc, err := registry.LoadOperations(filepath.Join(root, registry.OperationsPath))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := LoadSpec(filepath.Join(root, operationsYAML))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := New(spec, Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != len(yamlDoc.Operations) {
		t.Fatalf("registered=%d yaml=%d", len(reg.List()), len(yamlDoc.Operations))
	}
	for i, want := range yamlDoc.Operations {
		got, ok := reg.Lookup(want.ID)
		if !ok {
			t.Errorf("missing registration for %s", want.ID)
			continue
		}
		if got.ID != want.ID || got.RequestType != want.RequestType || got.ResponseType != want.ResponseType {
			t.Errorf("%s: id/types got=%s %s/%s want=%s/%s", want.ID, got.ID, got.RequestType, got.ResponseType, want.RequestType, want.ResponseType)
		}
		if got.Parity != want.Parity || got.Mutating != want.Mutating || got.Idempotent != want.Idempotent {
			t.Errorf("%s: metadata mismatch parity=%s mutating=%v idempotent=%s", want.ID, got.Parity, got.Mutating, got.Idempotent)
		}
		if !reflect.DeepEqual(got.Scopes, want.Scopes) {
			t.Errorf("%s: scopes=%v want=%v", want.ID, got.Scopes, want.Scopes)
		}
		if got.REST != (RESTBinding{Method: want.REST.Method, Path: want.REST.Path}) {
			t.Errorf("%s: REST=%+v want=%+v", want.ID, got.REST, want.REST)
		}
		if got.MCP.Kind != want.MCP.Kind || got.MCP.Name != want.MCP.Name || got.MCP.Resource != want.MCP.Resource || got.MCP.PullOperation != want.MCP.PullOperation {
			t.Errorf("%s: MCP=%+v want=%+v", want.ID, got.MCP, want.MCP)
		}
		if got.Request == nil || got.Request.Name() != want.RequestType {
			t.Errorf("%s: request Go type %v want %s", want.ID, got.Request, want.RequestType)
		}
		if got.Response == nil || got.Response.Name() != want.ResponseType {
			t.Errorf("%s: response Go type %v want %s", want.ID, got.Response, want.ResponseType)
		}
		listed := reg.List()[i]
		if listed.ID != want.ID {
			t.Errorf("list[%d]=%s want %s (YAML order)", i, listed.ID, want.ID)
		}
	}
}

func TestImplementedOperations(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	got := reg.ImplementedIDs()
	want := []string{
		IDEventsList, IDEventsSubscribe,
		IDPolicyEvaluate,
		IDSessionCreate, IDSessionDelete,
		IDSystemBuildGet, IDSystemStatusGet,
		IDTokensCreate, IDTokensList, IDTokensRevoke,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("implemented=%v want=%v", got, want)
	}
	for _, op := range reg.List() {
		switch op.ID {
		case IDSystemStatusGet, IDSystemBuildGet, IDPolicyEvaluate, IDEventsList, IDEventsSubscribe, IDTokensList, IDTokensCreate, IDTokensRevoke, IDSessionCreate, IDSessionDelete:
			if !op.Implemented {
				t.Errorf("%s should be implemented", op.ID)
			}
		default:
			if op.Implemented {
				t.Errorf("%s should be a stub", op.ID)
			}
		}
	}
}

func TestAssembleRejectsUnknownHandler(t *testing.T) {
	t.Parallel()
	spec := mustSpec(t)
	handlers := implementedHandlers(Deps{})
	handlers["not.in.yaml"] = stubHandler("not.in.yaml")
	_, err := assemble(spec, handlers, defaultCatalog())
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestAssembleRejectsMissingType(t *testing.T) {
	t.Parallel()
	spec := mustSpec(t)
	cat := defaultCatalog()
	delete(cat, "Status")
	_, err := assemble(spec, implementedHandlers(Deps{}), cat)
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestAssembleRejectsDuplicateSpecID(t *testing.T) {
	t.Parallel()
	spec := mustSpec(t)
	spec.Operations = append(spec.Operations, spec.Operations[0])
	_, err := assemble(spec, implementedHandlers(Deps{}), defaultCatalog())
	if !isCode(err, domain.CodeAlreadyExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestInvokeUnknownOperation(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), "does.not.exist", mustSnap(t, smallYAML), Input{Actor: reader})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestInvokeUnauthenticatedAndMissingScope(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, smallYAML)
	_, err := reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{})
	if !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("unauthenticated err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{
		Actor: Actor{ID: "tok", Scopes: []string{"events:read"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("scope err=%v", err)
	}
}

func TestInvokeStubUnavailable(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), "users.list", mustSnap(t, smallYAML), Input{Actor: reader})
	if !isCode(err, domain.CodeUnavailable) {
		t.Fatalf("err=%v", err)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Details["operation"] != "users.list" {
		t.Fatalf("detail=%v", err)
	}
}

func TestInvokeNilSnapshot(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), IDSystemStatusGet, nil, Input{Actor: reader})
	if !isCode(err, domain.CodeUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestInvokeWrongRequestType(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), IDSystemStatusGet, mustSnap(t, smallYAML), Input{
		Actor:   reader,
		Request: GetBuildRequest{},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestInvokeProtocolOnlyAllowsEmptyScopes(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	_, err := reg.Invoke(context.Background(), "health.live", mustSnap(t, smallYAML), Input{})
	if !isCode(err, domain.CodeUnavailable) {
		t.Fatalf("health stub should run without scopes, err=%v", err)
	}
}

func TestNewFromRepo(t *testing.T) {
	t.Parallel()
	reg, err := NewFromRepo(".", Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Lookup(IDSystemStatusGet); !ok {
		t.Fatal("status missing")
	}
}

func TestLoadSpecRejectsUnknownField(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ops.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\ntitle: t\noperations: []\nextra: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSpec(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func isCode(err error, code domain.Code) bool {
	if err == nil {
		return false
	}
	var de domain.Error
	if errors.As(err, &de) {
		return de.Code == code
	}
	return false
}

var reader = Actor{ID: "test-token", Scopes: []string{"state:read"}}

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := LoadRepoSpec(".")
	if err != nil {
		t.Fatal(err)
	}
	// Copy so tests can mutate.
	ops := append([]SpecOp(nil), spec.Operations...)
	return &Spec{SchemaVersion: spec.SchemaVersion, Title: spec.Title, Operations: ops}
}

func mustRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := New(mustSpec(t), Deps{Build: BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-12T00:00:00Z", UIVersion: "ui-test"}})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func mustSnap(t *testing.T, src string) *state.Snapshot {
	t.Helper()
	return mustMgr(t, src).Snapshot()
}

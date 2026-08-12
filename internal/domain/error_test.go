package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodesIncludeDesignSet(t *testing.T) {
	t.Parallel()
	want := []Code{
		CodeInvalidArgument,
		CodeNotFound,
		CodeAlreadyExists,
		CodeConflict,
		CodeRevisionMismatch,
		CodeUnauthenticated,
		CodePermissionDenied,
		CodeRateLimited,
		CodeUnavailable,
		CodeInternal,
		CodeClientMatchAmbiguous,
		CodeAuthMethodCredentialMissing,
	}
	for _, c := range want {
		if c == "" {
			t.Fatal("empty code")
		}
		e := NewError(c, "example")
		if e.Code != c {
			t.Fatalf("code=%q", e.Code)
		}
		if !errors.Is(e, NewError(c, "")) {
			t.Fatalf("errors.Is failed for %s", c)
		}
	}
}

func TestErrorErrorStringOmitsDetails(t *testing.T) {
	t.Parallel()
	e := NewError(CodeClientMatchAmbiguous, "tied clients").
		WithPath("clients").
		WithDetail("ids", []string{"a", "b"})
	got := e.Error()
	if got != "CLIENT_MATCH_AMBIGUOUS at clients: tied clients" {
		t.Fatalf("Error()=%q", got)
	}
	if e.Details["ids"] == nil {
		t.Fatal("details lost")
	}
}

func TestErrorWithDetailDoesNotMutateOriginal(t *testing.T) {
	t.Parallel()
	base := NewError(CodeConflict, "x").WithDetail("a", 1)
	next := base.WithDetail("b", 2)
	if _, ok := base.Details["b"]; ok {
		t.Fatal("WithDetail mutated the original Details map")
	}
	if next.Details["a"] != 1 || next.Details["b"] != 2 {
		t.Fatalf("next details=%v", next.Details)
	}
}

func TestAsError(t *testing.T) {
	t.Parallel()
	e := NewError(CodeNotFound, "missing")
	got, ok := AsError(e)
	if !ok || got.Code != CodeNotFound {
		t.Fatalf("AsError value: ok=%v got=%v", ok, got)
	}
	wrapped := fmt.Errorf("wrap: %w", e)
	got, ok = AsError(wrapped)
	if !ok || got.Code != CodeNotFound {
		t.Fatalf("AsError wrapped: ok=%v got=%v", ok, got)
	}
	if _, ok := AsError(errors.New("plain")); ok {
		t.Fatal("AsError on plain error")
	}
}

package auth

import (
	"reflect"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

func TestScopeMatrixExactMatch(t *testing.T) {
	t.Parallel()
	if !ValidScope("tokens:manage") || ValidScope("admin") {
		t.Fatal("valid")
	}
	got := Scopes()
	want := config.Scopes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes=%v want %v", got, want)
	}
	write := []string{"state:write"}
	if Satisfies(write, []string{"tokens:manage"}) {
		t.Fatal("state:write must not imply tokens:manage")
	}
	if Satisfies(write, []string{"runtime:reset"}) {
		t.Fatal("state:write must not imply runtime:reset")
	}
	if Satisfies(write, []string{"config:reload"}) {
		t.Fatal("state:write must not imply config:reload")
	}
	if !Satisfies(write, []string{"state:write"}) {
		t.Fatal("exact scope")
	}
	have := []string{"state:read", "events:read", "events:sensitive"}
	if !Satisfies(have, []string{"events:read", "events:sensitive"}) {
		t.Fatal("additional unrelated scopes are allowed")
	}
	if miss := Missing(have, []string{"events:read", "tokens:manage"}); !reflect.DeepEqual(miss, []string{"tokens:manage"}) {
		t.Fatalf("missing=%v", miss)
	}
	if !Has(have, "state:read") || Has(have, "state:write") {
		t.Fatal("Has")
	}
}

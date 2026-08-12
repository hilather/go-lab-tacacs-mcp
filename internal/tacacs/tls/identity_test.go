package tls

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

func TestWildcardMatch(t *testing.T) {
	t.Parallel()
	if !matchWildcard("*.tacacs.lab.example", "r1.tacacs.lab.example") {
		t.Fatal("expected match")
	}
	if matchWildcard("*.tacacs.lab.example", "tacacs.lab.example") {
		t.Fatal("wildcard must not match the bare suffix")
	}
	if matchWildcard("*.tacacs.lab.example", "a.b.tacacs.lab.example") {
		t.Fatal("wildcard is single-label only")
	}
	if matchWildcard("*.lab.example", "r1.lab.example") {
		t.Fatal("non-tacacs wildcard must not match")
	}
}

func TestValidateWildcardServerName(t *testing.T) {
	t.Parallel()
	if err := config.ValidateWildcardServerName("tacacs.lab.example"); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateWildcardServerName("*.tacacs.lab.example"); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateWildcardServerName("*.lab.example"); err == nil {
		t.Fatal("non-tacacs wildcard must be rejected")
	}
	if err := config.ValidateWildcardServerName("foo*.tacacs.lab.example"); err == nil {
		t.Fatal("partial-label wildcard must be rejected")
	}
}

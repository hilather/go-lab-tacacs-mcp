package auth

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const testToken = "lab-bootstrap-token-32-bytes!!!"

func TestAuthenticateBootstrapToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC)
	doc := &config.Document{
		API: config.API{
			BootstrapTokens: []config.BootstrapToken{{
				ID:     "lab-admin-token",
				Token:  config.SecretRef{File: "token", Purpose: credentials.PurposeAPIBearerToken},
				Scopes: []string{"state:read", "policy:test"},
			}},
		},
	}
	lookup := func(config.SecretRef) ([]byte, error) { return []byte(testToken), nil }
	v, err := Load(doc, lookup, fixedClock{t: now})
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Authenticate(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenID != "lab-admin-token" || len(p.Scopes) != 2 {
		t.Fatalf("principal=%+v", p)
	}
	if _, err := v.Authenticate("wrong-token-value-not-the-lab-one!"); err == nil {
		t.Fatal("expected unauthenticated")
	}
	if _, err := v.Authenticate(""); err == nil {
		t.Fatal("empty")
	}
}

func TestParseBearer(t *testing.T) {
	t.Parallel()
	tok, ok := ParseBearer("Bearer " + testToken)
	if !ok || tok != testToken {
		t.Fatalf("got %q %v", tok, ok)
	}
	if _, ok := ParseBearer("Basic x"); ok {
		t.Fatal("basic")
	}
	if _, ok := ParseBearer("Bearer"); ok {
		t.Fatal("bare")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	t.Parallel()
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	doc := &config.Document{
		API: config.API{
			BootstrapTokens: []config.BootstrapToken{{
				ID:        "old",
				Token:     config.SecretRef{File: "token", Purpose: credentials.PurposeAPIBearerToken},
				Scopes:    []string{"state:read"},
				ExpiresAt: &exp,
			}},
		},
	}
	v, err := Load(doc, func(config.SecretRef) ([]byte, error) { return []byte(testToken), nil }, fixedClock{t: exp.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Authenticate(testToken)
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeUnauthenticated {
		t.Fatalf("err=%v", err)
	}
}

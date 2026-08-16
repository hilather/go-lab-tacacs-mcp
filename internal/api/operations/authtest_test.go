package operations

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestRunAuthTestMustChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const pw = "labpass1!"
	phc, err := credentials.DeriveArgon2id([]byte(pw), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	if err := os.WriteFile(login, phc, 0o600); err != nil {
		t.Fatal(err)
	}
	src := `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
users:
  - id: alice
    must_change_login: true
    credentials:
      login:
        verifier: {file: ` + login + `}
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) {
		b, err := os.ReadFile(ref.File)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	}
	m, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{Params: credentials.TestParams})
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{Creds: creds, Secrets: lookup}
	snap := m.Snapshot()
	got := runAuthTest(context.Background(), deps, snap, TestAuthenticationRequest{
		UserID: "alice", Method: "ascii", Password: pw,
	}, config.AuthMethodASCII)
	if got != "must_change" {
		t.Fatalf("ascii status=%s", got)
	}
	got = runAuthTest(context.Background(), deps, snap, TestAuthenticationRequest{
		UserID: "alice", Method: "pap", Password: pw,
	}, config.AuthMethodPAP)
	if got != "must_change" {
		t.Fatalf("pap status=%s", got)
	}
	got = runAuthTest(context.Background(), deps, snap, TestAuthenticationRequest{
		UserID: "alice", Method: "ascii", Password: "wrong",
	}, config.AuthMethodASCII)
	if got != "fail" {
		t.Fatalf("wrong password status=%s", got)
	}

	rev := m.Revision()
	if _, err := m.UpdateUser("alice", state.UpdateUser{MustChangeLogin: boolPtr(false)}, &rev); err != nil {
		t.Fatal(err)
	}
	got = runAuthTest(context.Background(), deps, m.Snapshot(), TestAuthenticationRequest{
		UserID: "alice", Method: "ascii", Password: pw,
	}, config.AuthMethodASCII)
	if got != "pass" {
		t.Fatalf("cleared flag status=%s", got)
	}
}

func boolPtr(v bool) *bool { return &v }

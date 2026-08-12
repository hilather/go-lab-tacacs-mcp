package state

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestAuthenticateRuntimeToken(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	value, digest, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	mat := credentials.NewTokenMaterial([]byte(value))
	if !credentials.EqualDigest(digest, credentials.DigestToken(mat)) {
		t.Fatal("issued digest mismatch")
	}
	snap, err := m.CreateToken(CreateToken{ID: "rt", Name: "runtime", Scopes: []string{"state:read"}, Material: mat}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snap.AuthenticateToken([]byte(value), snap.CompiledAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "rt" || !got.Enabled {
		t.Fatalf("got=%+v", got)
	}
	if _, err := snap.AuthenticateToken([]byte("no-such-token"), snap.CompiledAt); !isUnauth(err) {
		t.Fatalf("unknown=%v", err)
	}
	if _, err := snap.AuthenticateToken(nil, snap.CompiledAt); !isUnauth(err) {
		t.Fatalf("empty=%v", err)
	}
	printed := fmt.Sprintf("%+v %#v", snap, snap.tokenIndex)
	if strings.Contains(printed, value) {
		t.Fatal("bearer leaked from snapshot")
	}
	sum := hex.EncodeToString(digest.Bytes())
	if strings.Contains(printed, sum) {
		t.Fatal("digest hex leaked from snapshot")
	}
}

func TestAuthenticateBootstrapToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "boot")
	const secret = "unit-test-bootstrap-token-canary-aabb"
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
api:
  bootstrap_tokens:
    - id: boot
      token: {file: %s}
      scopes: [state:read, tokens:manage]
`, secretPath)
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(doc, Options{
		Clock:   fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)},
		Secrets: config.FileLookup(config.ReadOptions{StrictFilesSet: true, StrictFiles: false}),
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := m.Snapshot()
	got, err := snap.AuthenticateToken([]byte(secret), snap.CompiledAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "boot" || len(got.Scopes) != 2 {
		t.Fatalf("got=%+v", got)
	}
	rev := snap.Revision
	if _, err := m.DeleteToken("boot", DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Snapshot().AuthenticateToken([]byte(secret), snap.CompiledAt); !isUnauth(err) {
		t.Fatalf("revoked still authenticates: %v", err)
	}
}

func TestAuthenticateExpiredToken(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	exp := m.Snapshot().CompiledAt.Add(-time.Minute)
	value, _, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	mat := credentials.NewTokenMaterial([]byte(value))
	snap, err := m.CreateToken(CreateToken{ID: "old", Name: "old", Scopes: []string{"state:read"}, Material: mat, ExpiresAt: &exp}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snap.AuthenticateToken([]byte(value), snap.CompiledAt); !isUnauth(err) {
		t.Fatalf("expired=%v", err)
	}
}

func isUnauth(err error) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == domain.CodeUnauthenticated
}

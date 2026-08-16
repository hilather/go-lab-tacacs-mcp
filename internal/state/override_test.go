package state

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestOverrideLoginVerifierAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	phc, err := credentials.DeriveArgon2id([]byte("new-login-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	snap, err := m.OverrideLoginVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("alice")
	if !ok || u.User.Credentials.Login.Verifier.MemoryID == "" {
		t.Fatalf("override ref=%+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File == "" {
		t.Fatal("challenge secret must be left on the file ref")
	}
	got, ok := snap.RuntimeSecret(u.User.Credentials.Login.Verifier.MemoryID)
	if !ok || !bytes.Equal(got, phc) {
		t.Fatalf("runtime material missing")
	}
	if !u.Capabilities.Login {
		t.Fatal("login capability must stay present")
	}

	bad := m.Revision()
	bad++
	if _, err := m.OverrideLoginVerifier("alice", phc, &bad); err == nil {
		t.Fatal("expected revision mismatch")
	} else if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeRevisionMismatch {
		t.Fatalf("err=%v", err)
	}
	if _, err := m.OverrideLoginVerifier("alice", []byte("not-a-phc"), nil); err == nil {
		t.Fatal("expected invalid PHC")
	}

	rev = m.Revision()
	after, err := m.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok = after.User("alice")
	if !ok || u.User.Credentials.Login.Verifier.MemoryID != "" || u.User.Credentials.Login.Verifier.File == "" {
		t.Fatalf("reset should restore baseline file ref: %+v", u.User.Credentials.Login.Verifier)
	}
	if _, ok := after.RuntimeSecret("login:alice"); ok {
		t.Fatal("reset must drop runtime material")
	}
}

func TestOverrideEnableVerifierAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	phc, err := credentials.DeriveArgon2id([]byte("new-enable-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	snap, err := m.OverrideEnableVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("alice")
	if !ok || u.User.Credentials.Enable.Verifier.MemoryID == "" {
		t.Fatalf("override ref=%+v", u.User.Credentials.Enable.Verifier)
	}
	if u.User.Credentials.Login.Verifier.File == "" || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatalf("login must stay on the file ref: %+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File == "" {
		t.Fatal("challenge secret must be left on the file ref")
	}
	got, ok := snap.RuntimeSecret(u.User.Credentials.Enable.Verifier.MemoryID)
	if !ok || !bytes.Equal(got, phc) {
		t.Fatalf("runtime material missing")
	}
	if !u.Capabilities.Enable {
		t.Fatal("enable capability must stay present")
	}

	bad := m.Revision()
	bad++
	if _, err := m.OverrideEnableVerifier("alice", phc, &bad); err == nil {
		t.Fatal("expected revision mismatch")
	} else if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeRevisionMismatch {
		t.Fatalf("err=%v", err)
	}
	if _, err := m.OverrideEnableVerifier("alice", []byte("not-a-phc"), nil); err == nil {
		t.Fatal("expected invalid PHC")
	}

	rev = m.Revision()
	after, err := m.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok = after.User("alice")
	if !ok || u.User.Credentials.Enable.Verifier.MemoryID != "" || u.User.Credentials.Enable.Verifier.File == "" {
		t.Fatalf("reset should restore baseline file ref: %+v", u.User.Credentials.Enable.Verifier)
	}
	if _, ok := after.RuntimeSecret("enable:alice"); ok {
		t.Fatal("reset must drop runtime material")
	}
}

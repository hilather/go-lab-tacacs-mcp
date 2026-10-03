package state

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
)

func TestDeletedUsersReleaseRuntimeVerifiers(t *testing.T) {
	m := mustMgr(t, smallYAML)
	phc, err := credentials.DeriveArgon2id([]byte("review-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("ephemeral-%d", i)
		if _, err = m.CreateUser(CreateUser{ID: id}, nil); err != nil {
			t.Fatal(err)
		}
		old, err := m.OverrideLoginVerifier(id, phc, nil)
		if err != nil {
			t.Fatal(err)
		}
		next, err := m.DeleteUser(id, DeleteOptions{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := next.RuntimeSecret("login:" + id); ok {
			t.Fatalf("deleted user %s retained verifier", id)
		}
		if _, ok := old.RuntimeSecret("login:" + id); !ok {
			t.Fatal("session-bound old snapshot lost verifier")
		}
	}
	if len(m.overlay.secrets) != 0 {
		t.Fatalf("orphaned secrets=%d", len(m.overlay.secrets))
	}
}

func TestFileVerifierReplacementReleasesRuntimeMaterial(t *testing.T) {
	for _, kind := range []string{"login", "enable"} {
		t.Run(kind, func(t *testing.T) {
			m := mustMgr(t, smallYAML)
			phc, err := credentials.DeriveArgon2id([]byte("review-replacement"), credentials.TestParams, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var old *Snapshot
			if kind == "login" {
				old, err = m.OverrideLoginVerifier("alice", phc, nil)
			} else {
				old, err = m.OverrideEnableVerifier("alice", phc, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			purpose := credentials.PurposeLoginVerifier
			if kind == "enable" {
				purpose = credentials.PurposeEnableVerifier
			}
			ref := config.SecretRef{File: "/run/secrets/replacement", Purpose: purpose}
			patch := UpdateUser{}
			if kind == "login" {
				patch.Login = &SecretPatch{Ref: ref}
			} else {
				patch.Enable = &SecretPatch{Ref: ref}
			}
			next, err := m.UpdateUser("alice", patch, nil)
			if err != nil {
				t.Fatal(err)
			}
			key := kind + ":alice"
			if _, ok := next.RuntimeSecret(key); ok {
				t.Fatal("file reference retained obsolete memory verifier")
			}
			if _, ok := old.RuntimeSecret(key); !ok {
				t.Fatal("old snapshot lost bound verifier")
			}
		})
	}
}

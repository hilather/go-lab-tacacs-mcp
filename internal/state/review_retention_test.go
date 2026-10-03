package state

import (
	"crypto/rand"
	"fmt"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"testing"
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

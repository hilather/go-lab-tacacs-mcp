package state

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestReloadRebaseKeepsOverlay(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("Runtime Alice")}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	next := mustParse(t, smallYAML)
	next.Metadata.Name = "reloaded"
	snap, err := m.Reload(next, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.DisplayName != "Runtime Alice" || u.Meta.Source != domain.SourceOverride {
		t.Fatalf("rebase dropped overlay: %+v", u)
	}
	if snap.Settings().Metadata.Name != "reloaded" {
		t.Fatalf("baseline name=%q", snap.Settings().Metadata.Name)
	}
}

func TestReloadRebaseRejectsInvalidCombination(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.CreateUser(CreateUser{ID: "carol", GroupIDs: &[]string{"ops"}}, &rev); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	rev = before.Revision
	// New baseline drops the ops group that carol references.
	next := mustParse(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    match:
      source_cidrs: ["10.20.0.0/16"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/sw}}
users:
  - id: alice
    credentials:
      login: {verifier: {file: /run/secrets/alice-login}}
`)
	_, err := m.Reload(next, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeGroupNotFound {
		t.Fatalf("got %v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("failed rebase must keep previous snapshot")
	}
	if _, ok := m.Snapshot().User("carol"); !ok {
		t.Fatal("overlay user lost after rejected rebase")
	}
}

func TestReloadResetDropsOverlay(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("tmp")}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	next := mustParse(t, smallYAML)
	next.Runtime.ReloadOverlayBehavior = "reset"
	snap, err := m.Reload(next, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.DisplayName != "Alice" || u.Meta.Source != domain.SourceConfig {
		t.Fatalf("reset reload: %+v", u)
	}
}

func TestValidateCandidateDoesNotPublish(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before := m.Revision()
	if err := m.ValidateCandidate(mustParse(t, smallYAML)); err != nil {
		t.Fatal(err)
	}
	if m.Revision() != before {
		t.Fatal("validate must not increment revision")
	}
	bad := mustParse(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
users:
  - id: x
    group_ids: [nope]
`)
	if err := m.ValidateCandidate(bad); err == nil {
		t.Fatal("expected error")
	}
	if m.Revision() != before {
		t.Fatal("validate failure published")
	}
}

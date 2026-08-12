package state

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestNewPublishesRevisionOne(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	s := m.Snapshot()
	if s.Revision != 1 {
		t.Fatalf("rev=%d", s.Revision)
	}
	u, ok := s.User("alice")
	if !ok || u.Meta.Source != domain.SourceConfig {
		t.Fatalf("alice=%+v ok=%v", u.Meta, ok)
	}
	if u.Meta.EffectiveRevision != 1 {
		t.Fatalf("effective=%d", u.Meta.EffectiveRevision)
	}
	if !u.Capabilities.Login || !u.Capabilities.Challenge || !u.Capabilities.Enable {
		t.Fatalf("capabilities=%+v", u.Capabilities)
	}
	g, ok := s.Group("ops")
	if !ok || len(g.Rules.Commands) != 1 || g.Rules.Commands[0].Command != nil {
		t.Fatalf("compiled group rules=%+v ok=%v", g.Rules, ok)
	}
}

func TestTombstoneHidesBaselineAndResetRestores(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	snap, err := m.DeleteUser("alice", DeleteOptions{ActorID: "tester"}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.User("alice"); ok {
		t.Fatal("tombstoned user listed")
	}
	tombs := snap.Tombstones()
	if len(tombs) != 1 || tombs[0].ID != "alice" || !tombs[0].Deleted {
		t.Fatalf("tombstones=%+v", tombs)
	}
	if string(tombs[0].Kind) == "tombstone" || tombs[0].Kind != domain.KindUser {
		t.Fatalf("kind=%s", tombs[0].Kind)
	}
	rev = snap.Revision
	if _, err := m.Reset(&rev); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Snapshot().User("alice"); !ok {
		t.Fatal("reset must restore baseline")
	}
	if len(m.Snapshot().Tombstones()) != 0 {
		t.Fatal("reset must drop tombstones")
	}
}

func TestDeleteOverrideRevealsBaseline(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("tmp")}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	if _, err := m.DeleteUser("alice", DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	u, ok := m.Snapshot().User("alice")
	if !ok || u.User.DisplayName != "Alice" || u.Meta.Source != domain.SourceConfig {
		t.Fatalf("revealed=%+v ok=%v", u, ok)
	}
}

func TestDeleteRuntimeRemoves(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.CreateUser(CreateUser{ID: "bob", DisplayName: strPtr("Bob")}, &rev); err != nil {
		t.Fatal(err)
	}
	u, ok := m.Snapshot().User("bob")
	if !ok || u.Meta.Source != domain.SourceRuntime {
		t.Fatalf("bob=%+v", u.Meta)
	}
	rev = m.Revision()
	if _, err := m.DeleteUser("bob", DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Snapshot().User("bob"); ok {
		t.Fatal("runtime delete must remove")
	}
}

func TestRevisionMismatchDoesNotPublish(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	stale := domain.Revision(99)
	_, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("nope")}, &stale)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeRevisionMismatch {
		t.Fatalf("got %v", err)
	}
	if m.Revision() != 1 {
		t.Fatalf("rev=%d", m.Revision())
	}
}

func TestInvalidMutationKeepsSnapshot(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before := m.Snapshot()
	rev := before.Revision
	_, err := m.UpdateUser("alice", UpdateUser{GroupIDs: &[]string{"missing-group"}}, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeGroupNotFound {
		t.Fatalf("got %v", err)
	}
	after := m.Snapshot()
	if after != before {
		t.Fatal("invalid candidate must not replace the pointer")
	}
	if after.Revision != 1 {
		t.Fatalf("rev=%d", after.Revision)
	}
}

func TestCreateGroupClientToken(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.CreateGroup(CreateGroup{ID: "netops", DisplayName: strPtr("NetOps")}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	if _, err := m.CreateClient(CreateClient{
		ID:           "core",
		Match:        &mustParse(t, smallYAML).Clients[0].Match,
		SharedSecret: &SecretPatch{Ref: mustParse(t, smallYAML).Clients[0].Legacy.SharedSecret},
	}, &rev); err != nil {
		t.Fatal(err)
	}
	// Distinct CIDR so the new client does not tie with sw.
	rev = m.Revision()
	_, err := m.UpdateClient("core", UpdateClient{
		Priority: intPtr(5),
		Match: &mustParse(t, `
schema_version: 1
listeners: {secure_tacacs: {enabled: false}}
clients:
  - id: x
    match:
      source_cidrs: ["172.16.0.0/12"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/core}}
`).Clients[0].Match,
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	mat := credentials.NewTokenMaterial([]byte("unit-test-token-material-11223344"))
	if _, err := m.CreateToken(CreateToken{ID: "tok1", Name: "one", Scopes: []string{"state:read"}, Material: mat}, &rev); err != nil {
		t.Fatal(err)
	}
	s := m.Snapshot()
	if _, ok := s.Group("netops"); !ok {
		t.Fatal("group")
	}
	if _, ok := s.Client("core"); !ok {
		t.Fatal("client")
	}
	tok, ok := s.Token("tok1")
	if !ok || !tok.HasDigest || tok.Meta.Source != domain.SourceRuntime {
		t.Fatalf("token=%+v ok=%v", tok, ok)
	}
	printed := fmt.Sprintf("%+v", s) + fmt.Sprintf("%v", tok)
	if strings.Contains(printed, "unit-test-token-material-11223344") {
		t.Fatal("token material leaked")
	}
}

func TestFreshManagerHasNoOverlay(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("x")}, &rev); err != nil {
		t.Fatal(err)
	}
	fresh, err := New(mustParse(t, smallYAML), Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := fresh.Snapshot().User("alice")
	if u.User.DisplayName != "Alice" || u.Meta.Source != domain.SourceConfig {
		t.Fatalf("restart leaked overlay: %+v", u)
	}
}

func TestTokenLimitUsesLiveSet(t *testing.T) {
	t.Parallel()
	const tokenYAML = `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
runtime:
  max_objects:
    api_tokens: 1
api:
  bootstrap_tokens:
    - id: boot
      token: {file: /run/secrets/boot}
      scopes: [state:read]
`
	t.Run("tombstone frees slot", func(t *testing.T) {
		t.Parallel()
		m := mustMgr(t, tokenYAML)
		rev := m.Revision()
		if _, err := m.DeleteToken("boot", DeleteOptions{}, &rev); err != nil {
			t.Fatal(err)
		}
		rev = m.Revision()
		mat := credentials.NewTokenMaterial([]byte("unit-test-token-material-aabbccdd"))
		if _, err := m.CreateToken(CreateToken{ID: "rt", Name: "rt", Scopes: []string{"state:read"}, Material: mat}, &rev); err != nil {
			t.Fatal(err)
		}
		if _, ok := m.Snapshot().Token("rt"); !ok {
			t.Fatal("runtime token missing")
		}
		if _, ok := m.Snapshot().Token("boot"); ok {
			t.Fatal("tombstoned bootstrap still live")
		}
	})
	t.Run("override is one identity", func(t *testing.T) {
		t.Parallel()
		m := mustMgr(t, tokenYAML)
		rev := m.Revision()
		mat := credentials.NewTokenMaterial([]byte("unit-test-token-material-eeff0011"))
		snap, err := m.CreateToken(CreateToken{ID: "boot", Name: "over", Scopes: []string{"state:read"}, Material: mat, Override: true}, &rev)
		if err != nil {
			t.Fatal(err)
		}
		tok, ok := snap.Token("boot")
		if !ok || tok.Meta.Source != domain.SourceOverride {
			t.Fatalf("override token=%+v ok=%v", tok, ok)
		}
	})
	t.Run("override rejected when shadowing disabled", func(t *testing.T) {
		t.Parallel()
		const noShadow = `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
runtime:
  allow_shadowing: false
api:
  bootstrap_tokens:
    - id: boot
      token: {file: /run/secrets/boot}
      scopes: [state:read]
`
		m := mustMgr(t, noShadow)
		rev := m.Revision()
		mat := credentials.NewTokenMaterial([]byte("unit-test-token-material-noshadow"))
		_, err := m.CreateToken(CreateToken{ID: "boot", Name: "over", Scopes: []string{"state:read"}, Material: mat, Override: true}, &rev)
		de, ok := domain.AsError(err)
		if !ok || de.Code != domain.CodeConflict {
			t.Fatalf("got %v", err)
		}
		if m.Revision() != 1 {
			t.Fatalf("published override: %d", m.Revision())
		}
		tok, ok := m.Snapshot().Token("boot")
		if !ok || tok.Meta.Source != domain.SourceConfig {
			t.Fatalf("baseline mutated: %+v ok=%v", tok, ok)
		}
	})
	t.Run("live over cap rejected", func(t *testing.T) {
		t.Parallel()
		m := mustMgr(t, tokenYAML)
		rev := m.Revision()
		mat := credentials.NewTokenMaterial([]byte("unit-test-token-material-22334455"))
		_, err := m.CreateToken(CreateToken{ID: "other", Name: "x", Scopes: []string{"state:read"}, Material: mat}, &rev)
		de, ok := domain.AsError(err)
		if !ok || de.Code != domain.CodeObjectLimitExceeded {
			t.Fatalf("got %v", err)
		}
		if m.Revision() != 1 {
			t.Fatalf("published over-cap: %d", m.Revision())
		}
	})
}

func TestConfigOnlyRevisionUpdatedStableAcrossOverlay(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	alice, _ := m.Snapshot().User("alice")
	if alice.Meta.RevisionUpdated != 1 || alice.Meta.RevisionCreated != 1 {
		t.Fatalf("initial meta=%+v", alice.Meta)
	}
	rev := m.Revision()
	if _, err := m.CreateUser(CreateUser{ID: "bob", DisplayName: strPtr("Bob")}, &rev); err != nil {
		t.Fatal(err)
	}
	alice, _ = m.Snapshot().User("alice")
	if alice.Meta.RevisionUpdated != 1 {
		t.Fatalf("overlay publish bumped config-only revision_updated=%d", alice.Meta.RevisionUpdated)
	}
	if alice.Meta.EffectiveRevision != 2 {
		t.Fatalf("effective_revision=%d", alice.Meta.EffectiveRevision)
	}
	rev = m.Revision()
	if _, err := m.Reload(mustParse(t, smallYAML), &rev); err != nil {
		t.Fatal(err)
	}
	alice, _ = m.Snapshot().User("alice")
	if alice.Meta.RevisionUpdated != m.Revision() {
		t.Fatalf("reload should bump baseline compile revision, got %d want %d", alice.Meta.RevisionUpdated, m.Revision())
	}
}

func TestInvalidOverlayIPSANRejected(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before := m.Snapshot()
	rev := before.Revision
	match := config.ClientMatch{
		SourceCIDRs: []string{"10.20.0.0/16"},
		Transports:  []domain.Transport{domain.TransportTLS},
		Mode:        domain.MatchCertificateOnly,
		Certificate: config.CertMatch{IPSANs: []string{"not-an-ip"}},
	}
	_, err := m.UpdateClient("sw", UpdateClient{Match: &match}, &rev)
	if err == nil {
		t.Fatal("expected invalid ip_sans to fail")
	}
	if m.Snapshot() != before {
		t.Fatal("invalid ip_sans published")
	}
}

func TestSourceNeverTombstone(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.DeleteUser("alice", DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	for _, tomb := range m.Snapshot().Tombstones() {
		if !tomb.Deleted {
			t.Fatal("deleted flag")
		}
	}
	for _, u := range m.Snapshot().Users() {
		if !u.Meta.Source.Valid() {
			t.Fatalf("invalid source %q", u.Meta.Source)
		}
	}
}

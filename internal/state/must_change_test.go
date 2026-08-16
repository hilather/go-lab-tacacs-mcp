package state

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const smallYAMLMustChange = `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
groups:
  - id: ops
    display_name: Operators
    priority: 10
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    must_change_login: true
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
      challenge:
        secret: {file: /run/secrets/alice-chal}
      enable:
        verifier: {file: /run/secrets/alice-enable}
`

const smallYAMLMustChangeEnable = `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
groups:
  - id: ops
    display_name: Operators
    priority: 10
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    must_change_enable: true
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
      challenge:
        secret: {file: /run/secrets/alice-chal}
      enable:
        verifier: {file: /run/secrets/alice-enable}
`

func TestUpdateUserMustChangeLoginAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	u, _ := m.Snapshot().User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("baseline flag must default false")
	}
	rev := m.Revision()
	snap, err := m.UpdateUser("alice", UpdateUser{MustChangeLogin: boolPtr(true)}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("alice")
	if !ok || !u.User.MustChangeLogin {
		t.Fatal("flag not set")
	}
	if u.Meta.Source != domain.SourceOverride {
		t.Fatalf("source=%s", u.Meta.Source)
	}
	rev = m.Revision()
	after, err := m.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = after.User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("reset must restore YAML false")
	}
}

func TestYAMLMustChangeRestoredAfterSuccessfulChangeAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAMLMustChange)
	u, _ := m.Snapshot().User("alice")
	if !u.User.MustChangeLogin {
		t.Fatal("YAML flag must load")
	}
	phc, err := credentials.DeriveArgon2id([]byte("changed-login-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	snap, err := m.OverrideLoginVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("override must clear flag")
	}
	if u.User.Credentials.Login.Verifier.MemoryID == "" {
		t.Fatal("runtime PHC missing")
	}
	rev = m.Revision()
	after, err := m.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = after.User("alice")
	if !u.User.MustChangeLogin {
		t.Fatal("reset must restore YAML flag")
	}
	if u.User.Credentials.Login.Verifier.File != "/run/secrets/alice-login" || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatalf("reset must restore YAML verifier: %+v", u.User.Credentials.Login.Verifier)
	}
}

func TestMustChangeFlipsBaselineHash(t *testing.T) {
	t.Parallel()
	plain := mustMgr(t, smallYAML).Snapshot().BaselineHash
	flagged := mustMgr(t, smallYAMLMustChange).Snapshot().BaselineHash
	if plain == flagged {
		t.Fatal("must_change_login must flip baseline_hash")
	}
}

func TestMustChangeFlipsOverlayHash(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before := m.Snapshot().OverlayHash
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	after := m.Snapshot().OverlayHash
	if before == after {
		t.Fatal("flag-only UpdateUser must flip overlay_hash")
	}
}

func TestPatchLoginSecretClearsMustChangeUnlessSet(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	snap, err := m.UpdateUser("alice", UpdateUser{
		Login: &SecretPatch{Ref: config.SecretRef{File: "/run/secrets/alice-login-2", Purpose: credentials.PurposeLoginVerifier}},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("non-nil login patch must clear flag when omitted")
	}

	rev = m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	snap, err = m.UpdateUser("alice", UpdateUser{
		Login:           &SecretPatch{Ref: config.SecretRef{File: "/run/secrets/alice-login-3", Purpose: credentials.PurposeLoginVerifier}},
		MustChangeLogin: boolPtr(true),
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if !u.User.MustChangeLogin {
		t.Fatal("same-patch true must keep flag")
	}

	rev = m.Revision()
	snap, err = m.UpdateUser("alice", UpdateUser{
		Enabled: boolPtr(false),
		Login:   &SecretPatch{Clear: true},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("Clear login must count as present and clear flag")
	}
	if u.User.Credentials.Login.Verifier.Set() {
		t.Fatal("login should be cleared")
	}
}

func TestMustChangeRejectedWhenLoginCleared(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	_, err := m.UpdateUser("alice", UpdateUser{
		Enabled:         boolPtr(false),
		Login:           &SecretPatch{Clear: true},
		MustChangeLogin: boolPtr(true),
	}, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("got %v", err)
	}
	u, _ := m.Snapshot().User("alice")
	if !u.User.Credentials.Login.Verifier.Set() || u.User.MustChangeLogin {
		t.Fatalf("invalid patch published: %+v", u.User)
	}
}

func TestUserFromCreatePassesMustChangeFields(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	snap, err := m.CreateUser(CreateUser{
		ID:              "bob",
		DisplayName:     strPtr("Bob"),
		Login:           &SecretPatch{Ref: config.SecretRef{File: "/run/secrets/bob-login", Purpose: credentials.PurposeLoginVerifier}},
		MustChangeLogin: boolPtr(true),
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("bob")
	if !ok || !u.User.MustChangeLogin {
		t.Fatalf("create dropped flag: %+v", u)
	}
}

func TestOverrideLoginVerifierClearsMustChange(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	phc, err := credentials.DeriveArgon2id([]byte("new-login-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	snap, err := m.OverrideLoginVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.MustChangeLogin {
		t.Fatal("OverrideLoginVerifier must clear MustChangeLogin")
	}
	got, ok := snap.RuntimeSecret(u.User.Credentials.Login.Verifier.MemoryID)
	if !ok || !bytes.Equal(got, phc) {
		t.Fatal("runtime material missing")
	}
}

func TestOverrideEnableVerifierClearsMustChange(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	if _, err := m.UpdateUser("alice", UpdateUser{MustChangeEnable: boolPtr(true), MustChangeLogin: boolPtr(true)}, &rev); err != nil {
		t.Fatal(err)
	}
	phc, err := credentials.DeriveArgon2id([]byte("new-enable-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev = m.Revision()
	snap, err := m.OverrideEnableVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.MustChangeEnable {
		t.Fatal("OverrideEnableVerifier must clear MustChangeEnable")
	}
	if !u.User.MustChangeLogin {
		t.Fatal("OverrideEnableVerifier must not clear MustChangeLogin")
	}
	if u.User.Credentials.Login.Verifier.File != "/run/secrets/alice-login" || u.User.Credentials.Login.Verifier.MemoryID != "" {
		t.Fatalf("login must be untouched: %+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File != "/run/secrets/alice-chal" {
		t.Fatal("challenge must be untouched")
	}
	if u.User.Credentials.Enable.Verifier.Purpose != credentials.PurposeEnableVerifier {
		t.Fatalf("purpose=%s", u.User.Credentials.Enable.Verifier.Purpose)
	}
	if u.User.Credentials.Enable.Verifier.MemoryID != "enable:alice" {
		t.Fatalf("memory key=%q", u.User.Credentials.Enable.Verifier.MemoryID)
	}
	got, ok := snap.RuntimeSecret(u.User.Credentials.Enable.Verifier.MemoryID)
	if !ok || !bytes.Equal(got, phc) {
		t.Fatal("runtime enable material missing")
	}
	if !u.Capabilities.Enable || !u.Capabilities.Login {
		t.Fatalf("capabilities=%+v", u.Capabilities)
	}
}

func TestYAMLMustChangeEnableRestoredAfterSuccessfulChangeAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAMLMustChangeEnable)
	u, _ := m.Snapshot().User("alice")
	if !u.User.MustChangeEnable {
		t.Fatal("YAML flag must load")
	}
	phc, err := credentials.DeriveArgon2id([]byte("changed-enable-secret"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	snap, err := m.OverrideEnableVerifier("alice", phc, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if u.User.MustChangeEnable {
		t.Fatal("override must clear flag")
	}
	if u.User.Credentials.Enable.Verifier.MemoryID == "" {
		t.Fatal("runtime PHC missing")
	}
	rev = m.Revision()
	after, err := m.Reset(&rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = after.User("alice")
	if !u.User.MustChangeEnable {
		t.Fatal("reset must restore YAML flag")
	}
	if u.User.Credentials.Enable.Verifier.File != "/run/secrets/alice-enable" || u.User.Credentials.Enable.Verifier.MemoryID != "" {
		t.Fatalf("reset must restore YAML verifier: %+v", u.User.Credentials.Enable.Verifier)
	}
}

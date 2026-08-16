package state

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const radiusPolicyYAML = `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: lab-switches
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/lab_switches_radius_secret}
          access_policy_id: default-radius-access
groups:
  - id: ops
    display_name: Operators
    priority: 10
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
radius_policies:
  - id: default-radius-access
    rules:
      - id: deny-rest
        effect: deny
  - id: admin-radius
    rules:
      - id: permit-admin
        effect: permit
`

func TestYAMLUserGroupRADIUSPolicyIDCompiled(t *testing.T) {
	t.Parallel()
	src := strings.Replace(radiusPolicyYAML, "    group_ids: [ops]\n", "    group_ids: [ops]\n    radius_policy_id: admin-radius\n", 1)
	src = strings.Replace(src, "    priority: 10\n", "    priority: 10\n    radius_policy_id: default-radius-access\n", 1)
	m := mustMgr(t, src)
	u, ok := m.Snapshot().User("alice")
	if !ok || u.User.RADIUSPolicyID != "admin-radius" {
		t.Fatalf("user policy=%+v", u.User)
	}
	g, ok := m.Snapshot().Group("ops")
	if !ok || g.Group.RADIUSPolicyID != "default-radius-access" {
		t.Fatalf("group policy=%+v", g.Group)
	}
}

func TestPatchUserRADIUSPolicyIDOmitKeepNullClearUnknownReject(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, radiusPolicyYAML)
	rev := m.Revision()
	snap, err := m.UpdateUser("alice", UpdateUser{RADIUSPolicyID: strPtr("admin-radius")}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := snap.User("alice")
	if u.User.RADIUSPolicyID != "admin-radius" {
		t.Fatalf("set=%q", u.User.RADIUSPolicyID)
	}

	rev = snap.Revision
	name := "Alice Overlay"
	snap, err = m.UpdateUser("alice", UpdateUser{DisplayName: &name}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if u.User.RADIUSPolicyID != "admin-radius" || u.User.DisplayName != name {
		t.Fatalf("omit must keep policy: %+v", u.User)
	}

	rev = snap.Revision
	snap, err = m.UpdateUser("alice", UpdateUser{RADIUSPolicyID: strPtr("")}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = snap.User("alice")
	if u.User.RADIUSPolicyID != "" {
		t.Fatalf("empty clears: %q", u.User.RADIUSPolicyID)
	}

	rev = snap.Revision
	if _, err = m.UpdateUser("alice", UpdateUser{RADIUSPolicyID: strPtr("missing")}, &rev); err == nil {
		t.Fatal("unknown policy id must fail closed")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	u, _ = m.Snapshot().User("alice")
	if u.User.RADIUSPolicyID != "" {
		t.Fatalf("failed patch mutated user: %q", u.User.RADIUSPolicyID)
	}
}

func TestPatchGroupRADIUSPolicyIDOmitKeepUnknownReject(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, radiusPolicyYAML)
	rev := m.Revision()
	snap, err := m.UpdateGroup("ops", UpdateGroup{RADIUSPolicyID: strPtr("admin-radius")}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := snap.Group("ops")
	if g.Group.RADIUSPolicyID != "admin-radius" {
		t.Fatalf("set=%q", g.Group.RADIUSPolicyID)
	}

	rev = snap.Revision
	prio := 11
	snap, err = m.UpdateGroup("ops", UpdateGroup{Priority: &prio}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	g, _ = snap.Group("ops")
	if g.Group.RADIUSPolicyID != "admin-radius" || g.Group.Priority != 11 {
		t.Fatalf("omit must keep policy: %+v", g.Group)
	}

	rev = snap.Revision
	if _, err = m.UpdateGroup("ops", UpdateGroup{RADIUSPolicyID: strPtr("missing")}, &rev); err == nil {
		t.Fatal("unknown policy id must fail closed")
	}
}

func TestCreateUserRADIUSPolicyIDAndReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, radiusPolicyYAML)
	rev := m.Revision()
	snap, err := m.CreateUser(CreateUser{
		ID:             "bob",
		Enabled:        boolPtr(true),
		RADIUSPolicyID: strPtr("admin-radius"),
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("bob")
	if !ok || u.User.RADIUSPolicyID != "admin-radius" {
		t.Fatalf("created=%+v", u.User)
	}

	rev = snap.Revision
	if _, err = m.Reset(&rev); err != nil {
		t.Fatal(err)
	}
	if _, ok = m.Snapshot().User("bob"); ok {
		t.Fatal("runtime user must vanish on reset")
	}
	alice, _ := m.Snapshot().User("alice")
	if alice.User.RADIUSPolicyID != "" {
		t.Fatalf("baseline alice should have empty policy: %q", alice.User.RADIUSPolicyID)
	}
}

func TestRADIUSPolicyIDFlipsBaselineHash(t *testing.T) {
	t.Parallel()
	plain := mustMgr(t, radiusPolicyYAML).Snapshot().BaselineHash
	src := strings.Replace(radiusPolicyYAML, "    group_ids: [ops]\n", "    group_ids: [ops]\n    radius_policy_id: admin-radius\n", 1)
	flagged := mustMgr(t, src).Snapshot().BaselineHash
	if plain == flagged {
		t.Fatal("user radius_policy_id must change baseline hash")
	}
}

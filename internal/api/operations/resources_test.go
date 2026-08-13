package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestUsersListGetCreateUpdateDelete(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}

	list, err := reg.Invoke(context.Background(), IDUsersList, m.Snapshot(), Input{Actor: writer})
	if err != nil {
		t.Fatal(err)
	}
	ul := list.Data.(UserList)
	if len(ul.Items) != 1 || ul.Items[0].ID != "alice" || !ul.Items[0].ASCIIPapConfigured {
		t.Fatalf("list=%+v", ul)
	}
	raw, _ := json.Marshal(ul)
	if strings.Contains(string(raw), "/run/secrets") || strings.Contains(string(raw), "verifier") {
		t.Fatalf("secret leaked: %s", raw)
	}

	got, err := reg.Invoke(context.Background(), IDUsersGet, m.Snapshot(), Input{Actor: writer, Request: GetUserRequest{ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Data.(User).DisplayName != "Alice" {
		t.Fatalf("get=%+v", got.Data)
	}

	enabled := false
	name := "Bob"
	created, err := reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateUserRequest{
			ID:          "bob",
			DisplayName: &name,
			Enabled:     &enabled,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Data.(User).Source != domain.SourceRuntime || created.Data.(User).ID != "bob" {
		t.Fatalf("create=%+v", created.Data)
	}

	rev := m.Revision()
	patchedName := "Bobby"
	updated, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "bob", DisplayName: &patchedName},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Data.(User).DisplayName != "Bobby" {
		t.Fatalf("update=%+v", updated.Data)
	}

	rev = m.Revision()
	_, err = reg.Invoke(context.Background(), IDUsersDelete, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          DeleteUserRequest{ID: "bob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Invoke(context.Background(), IDUsersGet, m.Snapshot(), Input{Actor: writer, Request: GetUserRequest{ID: "bob"}})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("deleted get err=%v", err)
	}
}

func TestUserPatchKeepsCredentials(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	name := "Alice Overlay"
	res, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "alice", DisplayName: &name},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := res.Data.(User)
	if !u.ASCIIPapConfigured || !u.ChallengeConfigured || !u.EnableConfigured {
		t.Fatalf("credentials dropped: %+v", u)
	}
	if u.Source != domain.SourceOverride {
		t.Fatalf("source=%s", u.Source)
	}
}

func TestGroupsAndClientsCRUD(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}

	gl, err := reg.Invoke(context.Background(), IDGroupsList, m.Snapshot(), Input{Actor: writer})
	if err != nil {
		t.Fatal(err)
	}
	if len(gl.Data.(GroupList).Items) != 1 || gl.Data.(GroupList).Items[0].ID != "ops" {
		t.Fatalf("groups=%+v", gl.Data)
	}

	prio := 20
	created, err := reg.Invoke(context.Background(), IDGroupsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateGroupRequest{
			ID:       "netops",
			Priority: &prio,
			CommandRules: &[]CommandRuleView{{
				ID: "ping", Priority: 10, Action: "permit_add",
				Command: MatchView{Exact: "ping"}, Arguments: MatchView{Pattern: ".*"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Data.(Group).ID != "netops" || len(created.Data.(Group).CommandRules) != 1 {
		t.Fatalf("group create=%+v", created.Data)
	}

	cl, err := reg.Invoke(context.Background(), IDClientsList, m.Snapshot(), Input{Actor: writer})
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.Data.(ClientList).Items) != 1 || cl.Data.(ClientList).Items[0].SharedSecretConfigured == false {
		t.Fatalf("clients=%+v", cl.Data)
	}
	raw, _ := json.Marshal(cl.Data)
	if strings.Contains(string(raw), "/run/secrets/sw") && strings.Contains(string(raw), "shared_secret\":") {
		// file path as configured flag is ok; raw secret bytes must not appear
	}
	if strings.Contains(string(raw), "supersecret") {
		t.Fatal("secret value leaked")
	}

	createdClient, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "ap",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.9.0.0/16"},
				Transports:  []string{"legacy"},
			},
			SharedSecret: OptionalSecret{Present: true, File: "/run/secrets/ap"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !createdClient.Data.(Client).SharedSecretConfigured {
		t.Fatalf("client=%+v", createdClient.Data)
	}
}

func TestConfigEffectiveExportValidateReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	src := smallYAML
	reg, err := New(mustSpec(t), Deps{
		State: m,
		LoadBaseline: func() (*config.Document, error) {
			return config.Parse([]byte(src))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := Actor{ID: "r", Scopes: []string{"state:read", "state:write", "config:export", "runtime:reset"}}

	eff, err := reg.Invoke(context.Background(), IDConfigEffectiveGet, m.Snapshot(), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	ec := eff.Data.(EffectiveConfig)
	if len(ec.Users) != 1 || ec.View != ConfigViewEffective {
		t.Fatalf("effective=%+v", ec)
	}

	exp, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	yamlOut := exp.Data.(ExportConfigResult).YAML
	if !strings.Contains(yamlOut, "redacted: true") || strings.Contains(yamlOut, "alice-login") {
		t.Fatalf("export leaked or missing placeholder:\n%s", yamlOut)
	}

	val, err := reg.Invoke(context.Background(), IDConfigValidate, m.Snapshot(), Input{
		Actor:   reader,
		Request: ValidateConfigRequest{YAML: smallYAML},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !val.Data.(ValidateConfigResult).Valid {
		t.Fatalf("validate=%+v", val.Data)
	}

	bad, err := reg.Invoke(context.Background(), IDConfigValidate, m.Snapshot(), Input{
		Actor:   reader,
		Request: ValidateConfigRequest{YAML: "schema_version: 1\nnot_a_field: 1\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bad.Data.(ValidateConfigResult).Valid {
		t.Fatal("invalid yaml reported valid")
	}

	name := "tmp"
	enabled := false
	if _, err := m.CreateUser(state.CreateUser{ID: "tmp", DisplayName: &name, Enabled: &enabled}, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot().Users()) != 2 {
		t.Fatalf("overlay user missing")
	}
	resetter := Actor{ID: "r", Scopes: []string{"runtime:reset"}}
	_, err = reg.Invoke(context.Background(), IDRuntimeReset, m.Snapshot(), Input{Actor: resetter})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot().Users()) != 1 {
		t.Fatalf("reset leftover users=%d", len(m.Snapshot().Users()))
	}
}

func TestAuthenticationTestFailClosed(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	tester := Actor{ID: "t", Scopes: []string{"policy:test"}}
	res, err := reg.Invoke(context.Background(), IDAuthenticationTest, m.Snapshot(), Input{
		Actor:   tester,
		Request: TestAuthenticationRequest{UserID: "alice", ClientID: "sw", Method: "ascii", Password: "unit-test-auth-canary-zz99"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := res.Data.(AuthenticationTestResult)
	if out.Status != "fail" {
		t.Fatalf("status=%s", out.Status)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "unit-test-auth-canary-zz99") {
		t.Fatalf("password leaked: %s", raw)
	}
}

func TestUsersRequireWriteScope(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	_, err := reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{
		Actor:   reader,
		Request: CreateUserRequest{ID: "x"},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("err=%v", err)
	}
}

func mustStateRegistry(t *testing.T, m *state.Manager) *Registry {
	t.Helper()
	reg, err := New(mustSpec(t), Deps{State: m})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

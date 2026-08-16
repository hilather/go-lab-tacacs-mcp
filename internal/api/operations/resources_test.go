package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
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
	if created.Revision != m.Snapshot().Revision || created.Data.(User).EffectiveRevision != created.Revision {
		t.Fatalf("create envelope rev=%d data=%d snap=%d", created.Revision, created.Data.(User).EffectiveRevision, m.Snapshot().Revision)
	}

	rev := created.Revision
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
	if updated.Revision != m.Snapshot().Revision || updated.Data.(User).EffectiveRevision != updated.Revision {
		t.Fatalf("update envelope rev=%d data=%d snap=%d", updated.Revision, updated.Data.(User).EffectiveRevision, m.Snapshot().Revision)
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
	if created.Revision != m.Snapshot().Revision {
		t.Fatalf("group create rev=%d snap=%d", created.Revision, m.Snapshot().Revision)
	}
	rev := created.Revision
	name := "Net Ops"
	updated, err := reg.Invoke(context.Background(), IDGroupsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateGroupRequest{ID: "netops", DisplayName: &name},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != m.Snapshot().Revision || updated.Data.(Group).DisplayName != "Net Ops" {
		t.Fatalf("group update=%+v rev=%d", updated.Data, updated.Revision)
	}
	rev = updated.Revision
	if _, err := reg.Invoke(context.Background(), IDGroupsDelete, m.Snapshot(), Input{
		Actor: writer, ExpectedRevision: &rev, Request: DeleteGroupRequest{ID: "netops"},
	}); err != nil {
		t.Fatal(err)
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
	if createdClient.Revision != m.Snapshot().Revision {
		t.Fatalf("client create rev=%d snap=%d", createdClient.Revision, m.Snapshot().Revision)
	}
	crev := createdClient.Revision
	cname := "Access"
	cupd, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &crev,
		Request:          UpdateClientRequest{ID: "ap", DisplayName: &cname},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cupd.Revision != m.Snapshot().Revision {
		t.Fatalf("client update rev=%d", cupd.Revision)
	}
	crev = cupd.Revision
	if _, err := reg.Invoke(context.Background(), IDClientsDelete, m.Snapshot(), Input{
		Actor: writer, ExpectedRevision: &crev, Request: DeleteClientRequest{ID: "ap"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigEffectiveExportValidateReset(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	src := smallYAML
	ring := events.New(32, nil)
	t.Cleanup(ring.Close)
	reg, err := New(mustSpec(t), Deps{
		State:  m,
		Events: ring,
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
	if !strings.Contains(yamlOut, "command_rules:") || !strings.Contains(yamlOut, "accounting:") {
		t.Fatalf("export missing non-secret fields:\n%s", yamlOut)
	}
	foundExport := false
	for _, ev := range ring.Read(events.Query{Limit: 20}).Items {
		if ev.Type == "api.config.exported" && ev.Result == "ok" {
			foundExport = true
			break
		}
	}
	if !foundExport {
		t.Fatal("missing api.config.exported audit")
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

func TestConfigReloadAndOverlayOrder(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	src := smallYAML
	var fail bool
	reg, err := New(mustSpec(t), Deps{
		State: m,
		LoadBaseline: func() (*config.Document, error) {
			if fail {
				return nil, domain.NewError(domain.CodeConfigYAMLInvalid, "mounted source is invalid")
			}
			return config.Parse([]byte(src))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write", "config:reload"}}
	enabled := false
	name := "aaa"
	if _, err := reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{
		Actor: writer, Request: CreateUserRequest{ID: "aaa", DisplayName: &name, Enabled: &enabled},
	}); err != nil {
		t.Fatal(err)
	}
	before := m.Revision()
	reloader := Actor{ID: "r", Scopes: []string{"config:reload"}}
	reloaded, err := reg.Invoke(context.Background(), IDConfigReload, m.Snapshot(), Input{Actor: reloader})
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Revision != m.Snapshot().Revision || reloaded.Revision <= before {
		t.Fatalf("reload rev=%d before=%d snap=%d", reloaded.Revision, before, m.Snapshot().Revision)
	}
	if _, ok := m.Snapshot().User("aaa"); !ok {
		t.Fatal("rebase dropped overlay user")
	}

	fail = true
	keep := m.Snapshot().Revision
	if _, err := reg.Invoke(context.Background(), IDConfigReload, m.Snapshot(), Input{Actor: reloader}); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if m.Snapshot().Revision != keep {
		t.Fatalf("failed reload published rev=%d want %d", m.Snapshot().Revision, keep)
	}

	rev := m.Revision()
	if _, err := reg.Invoke(context.Background(), IDUsersDelete, m.Snapshot(), Input{
		Actor: writer, ExpectedRevision: &rev, Request: DeleteUserRequest{ID: "alice", Tombstone: true},
	}); err != nil {
		t.Fatal(err)
	}
	ov, err := reg.Invoke(context.Background(), IDConfigEffectiveGet, m.Snapshot(), Input{
		Actor: reader, Request: GetEffectiveConfigRequest{View: ConfigViewOverlay},
	})
	if err != nil {
		t.Fatal(err)
	}
	users := ov.Data.(EffectiveConfig).Users
	if len(users) < 2 {
		t.Fatalf("overlay users=%+v", users)
	}
	for i := 1; i < len(users); i++ {
		if users[i-1].ID > users[i].ID {
			t.Fatalf("overlay users not sorted: %q then %q", users[i-1].ID, users[i].ID)
		}
	}
	listed, err := reg.Invoke(context.Background(), IDUsersList, m.Snapshot(), Input{
		Actor: reader, Request: ListUsersRequest{IncludeDeleted: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawDeleted bool
	for _, u := range listed.Data.(UserList).Items {
		if u.ID == "alice" && u.Deleted {
			sawDeleted = true
		}
	}
	if !sawDeleted {
		t.Fatalf("tombstone missing from include_deleted: %+v", listed.Data)
	}
}

func TestUsersCreateUpdateGetMustChangeFlags(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write", "config:export"}}

	got, err := reg.Invoke(context.Background(), IDUsersGet, m.Snapshot(), Input{Actor: writer, Request: GetUserRequest{ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	alice := got.Data.(User)
	if alice.MustChangeLogin || alice.MustChangeEnable {
		t.Fatalf("baseline flags default false: %+v", alice)
	}

	rev := m.Revision()
	updated, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "alice", MustChangeLogin: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := updated.Data.(User)
	if !u.MustChangeLogin || u.MustChangeEnable {
		t.Fatalf("update flags=%+v", u)
	}
	listed, err := reg.Invoke(context.Background(), IDUsersList, m.Snapshot(), Input{Actor: writer})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range listed.Data.(UserList).Items {
		if item.ID == "alice" {
			found = true
			if !item.MustChangeLogin || item.MustChangeEnable {
				t.Fatalf("list flags=%+v", item)
			}
		}
	}
	if !found {
		t.Fatal("alice missing from list")
	}

	created, err := reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateUserRequest{
			ID:               "qa-expire",
			Enabled:          boolPtr(true),
			Login:            OptionalSecret{Present: true, File: "/run/secrets/qa-login"},
			Enable:           OptionalSecret{Present: true, File: "/run/secrets/qa-enable"},
			MustChangeLogin:  boolPtr(true),
			MustChangeEnable: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	qa := created.Data.(User)
	if !qa.MustChangeLogin || !qa.MustChangeEnable {
		t.Fatalf("create flags=%+v", qa)
	}

	fetched, err := reg.Invoke(context.Background(), IDUsersGet, m.Snapshot(), Input{Actor: writer, Request: GetUserRequest{ID: "qa-expire"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fetched.Data.(User); !got.MustChangeLogin || !got.MustChangeEnable {
		t.Fatalf("get flags=%+v", got)
	}

	exp, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{Actor: writer})
	if err != nil {
		t.Fatal(err)
	}
	yamlOut := exp.Data.(ExportConfigResult).YAML
	if !strings.Contains(yamlOut, "must_change_login: true") || !strings.Contains(yamlOut, "must_change_enable: true") {
		t.Fatalf("export missing must_change keys:\n%s", yamlOut)
	}

	rev = m.Revision()
	_, err = reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          CreateUserRequest{ID: "no-login", MustChangeLogin: boolPtr(true)},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("flag without verifier err=%v", err)
	}
}

func TestBaselineViewKeepsYAMLMustChangeAfterOverlay(t *testing.T) {
	t.Parallel()
	src := strings.Replace(smallYAML, "    display_name: Alice\n", "    display_name: Alice\n    must_change_login: true\n", 1)
	m := mustMgr(t, src)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write", "config:export"}}

	rev := m.Revision()
	name := "Alice Overlay"
	if _, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "alice", DisplayName: &name},
	}); err != nil {
		t.Fatal(err)
	}

	eff, err := reg.Invoke(context.Background(), IDConfigEffectiveGet, m.Snapshot(), Input{
		Actor:   writer,
		Request: GetEffectiveConfigRequest{View: ConfigViewBaseline},
	})
	if err != nil {
		t.Fatal(err)
	}
	ec := eff.Data.(EffectiveConfig)
	if ec.View != ConfigViewBaseline {
		t.Fatalf("view=%s", ec.View)
	}
	found := false
	for _, u := range ec.Users {
		if u.ID != "alice" {
			continue
		}
		found = true
		if !u.MustChangeLogin || u.MustChangeEnable {
			t.Fatalf("baseline effective flags=%+v", u)
		}
	}
	if !found {
		t.Fatal("alice missing from baseline effective")
	}

	exp, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{
		Actor:   writer,
		Request: ExportConfigRequest{View: ConfigViewBaseline},
	})
	if err != nil {
		t.Fatal(err)
	}
	yamlOut := exp.Data.(ExportConfigResult).YAML
	if !strings.Contains(yamlOut, "must_change_login: true") {
		t.Fatalf("baseline export lost must_change_login:\n%s", yamlOut)
	}
}

func TestUsersUpdateOmitAndK9MustChange(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}

	rev := m.Revision()
	updated, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "alice", MustChangeLogin: boolPtr(true), MustChangeEnable: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := updated.Data.(User); !u.MustChangeLogin || !u.MustChangeEnable {
		t.Fatalf("flag-only update=%+v", u)
	}

	rev = updated.Revision
	name := "Alice Overlay"
	named, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request:          UpdateUserRequest{ID: "alice", DisplayName: &name},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := named.Data.(User); !u.MustChangeLogin || !u.MustChangeEnable || u.DisplayName != name {
		t.Fatalf("display-name omit must leave flags: %+v", u)
	}

	rev = named.Revision
	cleared, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateUserRequest{
			ID:    "alice",
			Login: OptionalSecret{Present: true, File: "/run/secrets/alice-login"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := cleared.Data.(User); u.MustChangeLogin || !u.MustChangeEnable {
		t.Fatalf("login omit flag must clear login only: %+v", u)
	}

	rev = cleared.Revision
	kept, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateUserRequest{
			ID:              "alice",
			Login:           OptionalSecret{Present: true, File: "/run/secrets/alice-login"},
			MustChangeLogin: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := kept.Data.(User); !u.MustChangeLogin {
		t.Fatalf("login + flag true must keep login flag: %+v", u)
	}

	rev = kept.Revision
	enCleared, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateUserRequest{
			ID:     "alice",
			Enable: OptionalSecret{Present: true, File: "/run/secrets/alice-enable"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := enCleared.Data.(User); u.MustChangeEnable || !u.MustChangeLogin {
		t.Fatalf("enable omit flag must clear enable only: %+v", u)
	}

	rev = enCleared.Revision
	enKept, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateUserRequest{
			ID:               "alice",
			Enable:           OptionalSecret{Present: true, File: "/run/secrets/alice-enable"},
			MustChangeEnable: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u := enKept.Data.(User); !u.MustChangeEnable {
		t.Fatalf("enable + flag true must keep enable flag: %+v", u)
	}
}

func TestUserMutationJSONRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"id":"alice","must_change_password":true}`,
		`{"id":"alice","restrictions":{"must_change_login":true}}`,
	} {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		var req UpdateUserRequest
		if err := dec.Decode(&req); err == nil {
			t.Fatalf("accepted unknown JSON %s", raw)
		}
	}
	dec := json.NewDecoder(strings.NewReader(`{"id":"alice","must_change_login":true}`))
	dec.DisallowUnknownFields()
	var req UpdateUserRequest
	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}
	if req.MustChangeLogin == nil || !*req.MustChangeLogin {
		t.Fatalf("decoded=%+v", req)
	}
}

func TestOptionalSecretRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	var s OptionalSecret
	err := json.Unmarshal([]byte(`{"file":"/run/secrets/x","value":"cleartext"}`), &s)
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
	var req CreateUserRequest
	if err := json.Unmarshal([]byte(`{"id":"x","login":{"file":"/run/secrets/x","value":"cleartext"}}`), &req); !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("nested err=%v", err)
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

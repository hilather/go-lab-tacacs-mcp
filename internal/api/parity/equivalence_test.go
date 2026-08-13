package parity

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

type parityCase struct {
	id        string
	req       any
	wantCode  string
	setup     func(*testing.T, *world)
	opts      func(*world) callOpts
	normalize func(any) any
	check     func(*testing.T, *world, callOut)
}

func parityCases() []parityCase {
	return []parityCase{
		{id: operations.IDSystemStatusGet, req: operations.GetStatusRequest{}},
		{id: operations.IDSystemBuildGet, req: operations.GetBuildRequest{}},
		{id: operations.IDConfigEffectiveGet, req: operations.GetEffectiveConfigRequest{}},
		{id: operations.IDConfigValidate, req: operations.ValidateConfigRequest{YAML: "schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\n"}},
		{id: operations.IDConfigValidate, req: operations.ValidateConfigRequest{YAML: "schema_version: 2\n"}},
		{id: operations.IDConfigReload, req: operations.ReloadConfigRequest{}},
		{id: operations.IDConfigExport, req: operations.ExportConfigRequest{}},
		{
			id:  operations.IDRuntimeReset,
			req: operations.ResetRuntimeRequest{},
			setup: func(t *testing.T, w *world) {
				t.Helper()
				enabled := false
				rev := w.Mgr.Revision()
				if _, err := w.Mgr.CreateUser(state.CreateUser{ID: "ephemeral", Enabled: &enabled}, &rev); err != nil {
					t.Fatal(err)
				}
			},
		},
		{id: operations.IDUsersList, req: operations.ListUsersRequest{}},
		{id: operations.IDUsersGet, req: operations.GetUserRequest{ID: "alice"}},
		{id: operations.IDUsersGet, req: operations.GetUserRequest{ID: "missing"}, wantCode: string(domain.CodeNotFound)},
		{id: operations.IDUsersCreate, req: operations.CreateUserRequest{ID: "bob", DisplayName: strPtr("Bob"), Enabled: boolPtr(false)}},
		{
			id:  operations.IDUsersUpdate,
			req: operations.UpdateUserRequest{ID: "alice", DisplayName: strPtr("Alice Prime")},
		},
		{
			id:  operations.IDUsersUpdate,
			req: operations.UpdateUserRequest{ID: "alice", DisplayName: strPtr("stale")},
			opts: func(*world) callOpts {
				bad := domain.Revision(999)
				return callOpts{ExpectedRevision: &bad}
			},
			wantCode: string(domain.CodeRevisionMismatch),
		},
		{
			id:  operations.IDUsersDelete,
			req: operations.DeleteUserRequest{ID: "bob"},
			setup: func(t *testing.T, w *world) {
				t.Helper()
				enabled := false
				rev := w.Mgr.Revision()
				if _, err := w.Mgr.CreateUser(state.CreateUser{ID: "bob", Enabled: &enabled}, &rev); err != nil {
					t.Fatal(err)
				}
			},
		},
		{id: operations.IDGroupsList, req: operations.ListGroupsRequest{}},
		{id: operations.IDGroupsGet, req: operations.GetGroupRequest{ID: "ops"}},
		{id: operations.IDGroupsCreate, req: operations.CreateGroupRequest{
			ID:       "netops",
			Priority: intPtr(20),
			CommandRules: &[]operations.CommandRuleView{{
				ID: "ping", Priority: 10, Action: "permit_add",
				Command: operations.MatchView{Exact: "ping"}, Arguments: operations.MatchView{Pattern: ".*"},
			}},
		}},
		{
			id:  operations.IDGroupsUpdate,
			req: operations.UpdateGroupRequest{ID: "ops", DisplayName: strPtr("Ops Overlay")},
		},
		{
			id:  operations.IDGroupsDelete,
			req: operations.DeleteGroupRequest{ID: "netops"},
			setup: func(t *testing.T, w *world) {
				t.Helper()
				prio := 20
				rev := w.Mgr.Revision()
				if _, err := w.Mgr.CreateGroup(state.CreateGroup{ID: "netops", Priority: &prio}, &rev); err != nil {
					t.Fatal(err)
				}
			},
		},
		{id: operations.IDClientsList, req: operations.ListClientsRequest{}},
		{id: operations.IDClientsGet, req: operations.GetClientRequest{ID: "sw"}},
		{id: operations.IDClientsCreate, req: operations.CreateClientRequest{
			ID: "ap",
			Match: &operations.ClientMatchView{
				SourceCIDRs: []string{"10.9.0.0/16"},
				Transports:  []string{"legacy"},
			},
			SharedSecret: operations.OptionalSecret{Present: true, File: "/run/secrets/ap"},
		}},
		{
			id:  operations.IDClientsUpdate,
			req: operations.UpdateClientRequest{ID: "sw", DisplayName: strPtr("Core Switches")},
		},
		{
			id:  operations.IDClientsDelete,
			req: operations.DeleteClientRequest{ID: "ap"},
			setup: func(t *testing.T, w *world) {
				t.Helper()
				_, err := w.Registry.Invoke(context.Background(), operations.IDClientsCreate, w.Mgr.Snapshot(), operations.Input{
					Actor: w.Actor,
					Request: operations.CreateClientRequest{
						ID: "ap",
						Match: &operations.ClientMatchView{
							SourceCIDRs: []string{"10.9.0.0/16"},
							Transports:  []string{"legacy"},
						},
						SharedSecret: operations.OptionalSecret{Present: true, File: "/run/secrets/ap"},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{id: operations.IDTokensList, req: operations.ListTokensRequest{}},
		{
			id: operations.IDTokensCreate,
			req: operations.CreateTokenRequest{
				ID:     "once",
				Name:   "once",
				Scopes: []string{"state:read"},
			},
			normalize: stripTokenField,
			check: func(t *testing.T, w *world, out callOut) {
				t.Helper()
				tok := tokenValue(out.Data)
				if tok == "" {
					t.Fatalf("one-time token missing data=%s", canonicalJSON(out.Data))
				}
				listed := invoke(t, w, operations.IDTokensList, operations.ListTokensRequest{}, callOpts{})
				raw := canonicalJSON(listed.Data)
				if strings.Contains(raw, tok) {
					t.Fatal("one-time token persisted in list")
				}
				exp := invoke(t, w, operations.IDConfigExport, operations.ExportConfigRequest{}, callOpts{})
				if strings.Contains(canonicalJSON(exp.Data), tok) {
					t.Fatal("one-time token persisted in export")
				}
			},
		},
		{
			id:  operations.IDTokensRevoke,
			req: operations.RevokeTokenRequest{ID: "temp"},
			setup: func(t *testing.T, w *world) {
				t.Helper()
				rev := w.Mgr.Revision()
				if _, err := w.Mgr.CreateToken(state.CreateToken{
					ID:       "temp",
					Name:     "temp",
					Scopes:   []string{"state:read"},
					Material: credentials.NewTokenMaterial([]byte("parity-temp-token-material-32b!!")),
				}, &rev); err != nil {
					t.Fatal(err)
				}
			},
		},
		{id: operations.IDPolicyEvaluate, req: operations.EvaluatePolicyRequest{
			UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show",
		}},
		{id: operations.IDPolicyEvaluate, req: operations.EvaluatePolicyRequest{Service: "shell"}, wantCode: string(domain.CodeInvalidArgument)},
		{id: operations.IDAuthenticationTest, req: operations.TestAuthenticationRequest{
			UserID: "alice", Method: "ascii", Password: "parity-auth-canary-not-a-secret",
		}, check: func(t *testing.T, _ *world, out callOut) {
			t.Helper()
			if strings.Contains(canonicalJSON(out.Data), "parity-auth-canary-not-a-secret") {
				t.Fatal("password leaked from authentication.test")
			}
		}},
		{id: operations.IDEventsList, req: operations.ListEventsRequest{Limit: 10}},
	}
}

func TestParityRequiredEquivalence(t *testing.T) {
	t.Parallel()
	for _, tc := range parityCases() {
		tc := tc
		name := tc.id
		if tc.wantCode != "" {
			name += "/" + tc.wantCode
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			direct, restW, mcpW := isolatedTrio(t, allScopes)
			for _, w := range []*world{direct, restW, mcpW} {
				if tc.setup != nil {
					tc.setup(t, w)
				}
			}
			var opts callOpts
			if tc.opts != nil {
				opts = tc.opts(direct)
			}
			d := invoke(t, direct, tc.id, tc.req, opts)
			r := invoke(t, restW, tc.id, tc.req, opts)
			m := invoke(t, mcpW, tc.id, tc.req, opts)
			if tc.wantCode != "" {
				if d.Code != tc.wantCode || r.Code != tc.wantCode || m.Code != tc.wantCode {
					t.Fatalf("codes direct=%q rest=%q mcp=%q want=%q", d.Code, r.Code, m.Code, tc.wantCode)
				}
				return
			}
			if d.Code != "" || r.Code != "" || m.Code != "" {
				t.Fatalf("unexpected errors direct=%q rest=%q mcp=%q restBody=%s mcpBody=%s", d.Code, r.Code, m.Code, r.Raw, m.Raw)
			}
			compareWorlds(t, tc.id, direct, restW, d, r, tc.normalize)
			compareWorlds(t, tc.id, restW, mcpW, r, m, tc.normalize)
			if tc.check != nil {
				tc.check(t, direct, d)
				tc.check(t, restW, r)
				tc.check(t, mcpW, m)
			}
		})
	}
}

func TestEveryParityRequiredHasCase(t *testing.T) {
	t.Parallel()
	spec, err := operations.LoadRepoSpec(".")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]struct{}{}
	for _, tc := range parityCases() {
		have[tc.id] = struct{}{}
	}
	have[operations.IDEventsSubscribe] = struct{}{}
	for _, op := range spec.Operations {
		if op.Parity != registry.ParityRequired {
			continue
		}
		if _, ok := have[op.ID]; !ok {
			t.Errorf("PARITY_REQUIRED %s has no equivalence case", op.ID)
		}
	}
}

func TestEmptyOptionalSecretObject(t *testing.T) {
	t.Parallel()
	_, restW, mcpW := isolatedTrio(t, allScopes)
	body := map[string]any{"id": "alice", "login": map[string]any{}}
	r := invoke(t, restW, operations.IDUsersUpdate, operations.UpdateUserRequest{ID: "alice"}, callOpts{Body: body})
	m := invoke(t, mcpW, operations.IDUsersUpdate, operations.UpdateUserRequest{ID: "alice"}, callOpts{Body: body})
	if r.Code != m.Code {
		t.Fatalf("rest=%q mcp=%q restBody=%s mcpBody=%s", r.Code, m.Code, r.Raw, m.Raw)
	}
	if r.Code != string(domain.CodeAuthMethodCredentialMissing) && r.Code != string(domain.CodeInvalidArgument) {
		t.Fatalf("login:{} code=%q want credential-missing or invalid_argument restBody=%s", r.Code, r.Raw)
	}
}

func TestIdempotentCreateSameFailure(t *testing.T) {
	t.Parallel()
	direct, restW, mcpW := isolatedTrio(t, allScopes)
	req := operations.CreateUserRequest{ID: "dup", Enabled: boolPtr(false)}
	opts := callOpts{IdempotencyKey: "create-dup"}
	for _, w := range []*world{direct, restW, mcpW} {
		first := invoke(t, w, operations.IDUsersCreate, req, opts)
		if first.Code != "" {
			t.Fatalf("%s first create: %s %s", w.Name, first.Code, first.Raw)
		}
		second := invoke(t, w, operations.IDUsersCreate, req, opts)
		if second.Code != string(domain.CodeAlreadyExists) {
			t.Fatalf("%s replay code=%q want already_exists (no replay store)", w.Name, second.Code)
		}
	}
}

func TestDirectInvokeMatchesRESTAndMCP(t *testing.T) {
	t.Parallel()
	direct, restW, mcpW := isolatedTrio(t, allScopes)
	req := operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell"}
	d, err := direct.Registry.Invoke(context.Background(), operations.IDPolicyEvaluate, direct.Mgr.Snapshot(), operations.Input{
		Actor:   direct.Actor,
		Request: req,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := invoke(t, restW, operations.IDPolicyEvaluate, req, callOpts{})
	m := invoke(t, mcpW, operations.IDPolicyEvaluate, req, callOpts{})
	want := canonicalJSON(asJSONValue(d.Data))
	if canonicalJSON(r.Data) != want || canonicalJSON(m.Data) != want {
		t.Fatalf("direct=%s rest=%s mcp=%s", want, canonicalJSON(r.Data), canonicalJSON(m.Data))
	}
}

func stripTokenField(v any) any {
	m := asMap(v)
	delete(m, "token")
	return m
}

func tokenValue(v any) string {
	m, _ := v.(map[string]any)
	s, _ := m["token"].(string)
	return s
}

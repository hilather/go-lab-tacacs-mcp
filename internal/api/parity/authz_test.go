package parity

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/tools/registry"
)

func TestAuthorizationEquivalence(t *testing.T) {
	t.Parallel()
	reg := newWorld(t, "direct", allScopes, "").Registry
	reqs := authzRequests()
	var tools []operations.Operation
	for _, op := range reg.List() {
		if op.Parity != registry.ParityRequired || op.MCP.Kind != "tool" {
			continue
		}
		if _, ok := reqs[op.ID]; !ok {
			t.Errorf("PARITY_REQUIRED tool %s missing authz request", op.ID)
			continue
		}
		tools = append(tools, op)
	}
	if len(tools) == 0 {
		t.Fatal("no PARITY_REQUIRED tools")
	}

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		assertAuthzAll(t, tools, reqs, allScopes, callOpts{OmitAuth: true}, string(domain.CodeUnauthenticated))
	})
	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		assertAuthzAll(t, tools, reqs, allScopes, callOpts{Token: "not-a-valid-bearer-token"}, string(domain.CodeUnauthenticated))
	})
	t.Run("expired_token", func(t *testing.T) {
		t.Parallel()
		_, restW, mcpW := isolatedTrio(t, allScopes)
		past := parityClock.Now().Add(-time.Hour)
		value, _, err := credentials.IssueBearer(nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []*world{restW, mcpW} {
			rev := w.Mgr.Revision()
			if _, err := w.Mgr.CreateToken(state.CreateToken{
				ID:        "expired",
				Name:      "expired",
				Scopes:    allScopes,
				ExpiresAt: &past,
				Material:  credentials.NewTokenMaterial([]byte(value)),
			}, &rev); err != nil {
				t.Fatal(err)
			}
		}
		for _, op := range tools {
			r := invoke(t, restW, op.ID, reqs[op.ID], callOpts{Token: value})
			m := invoke(t, mcpW, op.ID, reqs[op.ID], callOpts{Token: value})
			if r.Code != string(domain.CodeUnauthenticated) || m.Code != string(domain.CodeUnauthenticated) {
				t.Errorf("%s expired rest=%q mcp=%q", op.ID, r.Code, m.Code)
			}
		}
	})
	t.Run("missing_scope", func(t *testing.T) {
		t.Parallel()
		assertAuthzAll(t, tools, reqs, []string{"events:sensitive"}, callOpts{}, string(domain.CodePermissionDenied))
	})
	t.Run("exact_scope", func(t *testing.T) {
		t.Parallel()
		for _, op := range tools {
			op := op
			t.Run(op.ID, func(t *testing.T) {
				t.Parallel()
				assertAuthzAllowed(t, op.ID, reqs[op.ID], op.Scopes)
			})
		}
	})
	t.Run("extra_scopes", func(t *testing.T) {
		t.Parallel()
		for _, op := range tools {
			op := op
			t.Run(op.ID, func(t *testing.T) {
				t.Parallel()
				assertAuthzAllowed(t, op.ID, reqs[op.ID], allScopes)
			})
		}
	})
}

func TestExpiredTokenDeniedEquivalently(t *testing.T) {
	t.Parallel()
	_, restW, mcpW := isolatedTrio(t, allScopes)
	past := parityClock.Now().Add(-time.Hour)
	for _, w := range []*world{restW, mcpW} {
		rev := w.Mgr.Revision()
		value, _, err := credentials.IssueBearer(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Mgr.CreateToken(state.CreateToken{
			ID:        "expired",
			Name:      "expired",
			Scopes:    []string{"state:read"},
			ExpiresAt: &past,
			Material:  credentials.NewTokenMaterial([]byte(value)),
		}, &rev); err != nil {
			t.Fatal(err)
		}
		out := invoke(t, w, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{Token: value})
		if out.Code != string(domain.CodeUnauthenticated) {
			t.Fatalf("%s expired token code=%q body=%s", w.Name, out.Code, out.Raw)
		}
	}
}

func assertAuthzAll(t *testing.T, tools []operations.Operation, reqs map[string]any, scopes []string, opts callOpts, want string) {
	t.Helper()
	_, restW, mcpW := isolatedTrio(t, scopes)
	for _, op := range tools {
		r := invoke(t, restW, op.ID, reqs[op.ID], opts)
		m := invoke(t, mcpW, op.ID, reqs[op.ID], opts)
		if r.Code != want || m.Code != want {
			t.Errorf("%s rest=%q mcp=%q want=%q restBody=%s mcpBody=%s", op.ID, r.Code, m.Code, want, r.Raw, m.Raw)
		}
	}
}

func assertAuthzAllowed(t *testing.T, id string, req any, scopes []string) {
	t.Helper()
	_, restW, mcpW := isolatedTrio(t, scopes)
	r := invoke(t, restW, id, req, callOpts{})
	m := invoke(t, mcpW, id, req, callOpts{})
	if r.Code != m.Code {
		t.Fatalf("%s rest=%q mcp=%q restBody=%s mcpBody=%s", id, r.Code, m.Code, r.Raw, m.Raw)
	}
	if r.Code == string(domain.CodeUnauthenticated) || r.Code == string(domain.CodePermissionDenied) {
		t.Fatalf("%s denied with required scopes: %s", id, r.Code)
	}
}

func authzRequests() map[string]any {
	return map[string]any{
		operations.IDSystemStatusGet:    operations.GetStatusRequest{},
		operations.IDSystemBuildGet:     operations.GetBuildRequest{},
		operations.IDConfigEffectiveGet: operations.GetEffectiveConfigRequest{},
		operations.IDConfigValidate:     operations.ValidateConfigRequest{YAML: "schema_version: 1\n"},
		operations.IDConfigReload:       operations.ReloadConfigRequest{},
		operations.IDConfigExport:       operations.ExportConfigRequest{},
		operations.IDRuntimeReset:       operations.ResetRuntimeRequest{},
		operations.IDUsersList:          operations.ListUsersRequest{},
		operations.IDUsersGet:           operations.GetUserRequest{ID: "alice"},
		operations.IDUsersCreate:        operations.CreateUserRequest{ID: "authz-user", Enabled: boolPtr(false)},
		operations.IDUsersUpdate:        operations.UpdateUserRequest{ID: "alice", DisplayName: strPtr("Authz")},
		operations.IDUsersDelete:        operations.DeleteUserRequest{ID: "nosuch-user"},
		operations.IDGroupsList:         operations.ListGroupsRequest{},
		operations.IDGroupsGet:          operations.GetGroupRequest{ID: "ops"},
		operations.IDGroupsCreate:       operations.CreateGroupRequest{ID: "authz-group", Priority: intPtr(30)},
		operations.IDGroupsUpdate:       operations.UpdateGroupRequest{ID: "ops", DisplayName: strPtr("Authz Ops")},
		operations.IDGroupsDelete:       operations.DeleteGroupRequest{ID: "nosuch-group"},
		operations.IDClientsList:        operations.ListClientsRequest{},
		operations.IDClientsGet:         operations.GetClientRequest{ID: "sw"},
		operations.IDClientsCreate: operations.CreateClientRequest{
			ID: "authz-client",
			Match: &operations.ClientMatchView{
				SourceCIDRs: []string{"10.8.0.0/16"},
				Transports:  []string{"legacy"},
			},
			SharedSecret: operations.OptionalSecret{Present: true, File: "/run/secrets/authz"},
		},
		operations.IDClientsUpdate: operations.UpdateClientRequest{ID: "sw", DisplayName: strPtr("Authz Sw")},
		operations.IDClientsDelete: operations.DeleteClientRequest{ID: "nosuch-client"},
		operations.IDTokensList:    operations.ListTokensRequest{},
		operations.IDTokensCreate: operations.CreateTokenRequest{
			ID: "authz-token", Name: "authz-token", Scopes: []string{"state:read"},
		},
		operations.IDTokensRevoke: operations.RevokeTokenRequest{ID: "nosuch-token"},
		operations.IDPolicyEvaluate: operations.EvaluatePolicyRequest{
			UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show",
		},
		operations.IDAuthenticationTest: operations.TestAuthenticationRequest{UserID: "alice", Method: "ascii"},
		operations.IDRadiusAccessTest: operations.RadiusAccessTestRequest{
			UserID: "alice", Method: operations.RadiusAuthMethod{Type: "pap"},
		},
		operations.IDRadiusPolicyEvaluate: operations.RadiusPolicyEvaluateRequest{
			UserID: "alice", ClientID: "sw", Method: "pap",
		},
		operations.IDRadiusAttributesList: operations.ListRadiusAttributesRequest{},
		operations.IDEventsList:           operations.ListEventsRequest{Limit: 5},
	}
}

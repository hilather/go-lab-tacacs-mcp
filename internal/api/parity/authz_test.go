package parity

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestAuthorizationEquivalence(t *testing.T) {
	t.Parallel()
	type authzCase struct {
		id     string
		req    any
		scopes []string
	}
	ops := []authzCase{
		{operations.IDSystemStatusGet, operations.GetStatusRequest{}, []string{"state:read"}},
		{operations.IDUsersCreate, operations.CreateUserRequest{ID: "scoped", Enabled: boolPtr(false)}, []string{"state:write"}},
		{operations.IDPolicyEvaluate, operations.EvaluatePolicyRequest{UserID: "alice", Service: "shell"}, []string{"policy:test"}},
		{operations.IDEventsList, operations.ListEventsRequest{Limit: 5}, []string{"events:read"}},
		{operations.IDTokensList, operations.ListTokensRequest{}, []string{"tokens:manage"}},
		{operations.IDConfigExport, operations.ExportConfigRequest{}, []string{"config:export"}},
		{operations.IDConfigReload, operations.ReloadConfigRequest{}, []string{"config:reload"}},
		{operations.IDRuntimeReset, operations.ResetRuntimeRequest{}, []string{"runtime:reset"}},
	}
	for _, op := range ops {
		op := op
		t.Run(op.id, func(t *testing.T) {
			t.Parallel()
			t.Run("no_token", func(t *testing.T) {
				t.Parallel()
				assertAuthz(t, op.id, op.req, allScopes, callOpts{OmitAuth: true}, string(domain.CodeUnauthenticated))
			})
			t.Run("invalid_token", func(t *testing.T) {
				t.Parallel()
				assertAuthz(t, op.id, op.req, allScopes, callOpts{Token: "not-a-valid-bearer-token"}, string(domain.CodeUnauthenticated))
			})
			t.Run("missing_scope", func(t *testing.T) {
				t.Parallel()
				assertAuthz(t, op.id, op.req, []string{"events:sensitive"}, callOpts{}, string(domain.CodePermissionDenied))
			})
			t.Run("exact_scope", func(t *testing.T) {
				t.Parallel()
				assertAuthz(t, op.id, op.req, op.scopes, callOpts{}, "")
			})
			t.Run("extra_scopes", func(t *testing.T) {
				t.Parallel()
				assertAuthz(t, op.id, op.req, allScopes, callOpts{}, "")
			})
		})
	}
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

func assertAuthz(t *testing.T, id string, req any, scopes []string, opts callOpts, wantCode string) {
	t.Helper()
	_, restW, mcpW := isolatedTrio(t, scopes)
	if wantCode == string(domain.CodePermissionDenied) {
		op, _ := restW.Registry.Lookup(id)
		if containsAll(scopes, op.Scopes) {
			t.Skip("provided scopes already satisfy the operation")
		}
	}
	r := invoke(t, restW, id, req, opts)
	m := invoke(t, mcpW, id, req, opts)
	if r.Code != wantCode || m.Code != wantCode {
		t.Fatalf("rest=%q mcp=%q want=%q restBody=%s mcpBody=%s", r.Code, m.Code, wantCode, r.Raw, m.Raw)
	}
}

func contains(have []string, want string) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
}

func containsAll(have, need []string) bool {
	for _, n := range need {
		if !contains(have, n) {
			return false
		}
	}
	return true
}

package parity

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func TestRedactionEquivalence(t *testing.T) {
	t.Parallel()
	const (
		passCanary  = "unit-test-parity-password-canary-zz91"
		tokenCanary = "unit-test-parity-invalid-token-canary-zz91"
	)
	direct, restW, mcpW := isolatedTrio(t, allScopes)
	reads := []struct {
		id  string
		req any
	}{
		{operations.IDSystemStatusGet, operations.GetStatusRequest{}},
		{operations.IDUsersList, operations.ListUsersRequest{}},
		{operations.IDUsersGet, operations.GetUserRequest{ID: "alice"}},
		{operations.IDClientsList, operations.ListClientsRequest{}},
		{operations.IDConfigEffectiveGet, operations.GetEffectiveConfigRequest{}},
		{operations.IDConfigExport, operations.ExportConfigRequest{}},
		{operations.IDEventsList, operations.ListEventsRequest{Limit: 20}},
		{operations.IDTokensList, operations.ListTokensRequest{}},
	}
	for _, w := range []*world{direct, restW, mcpW} {
		authn := invoke(t, w, operations.IDAuthenticationTest, operations.TestAuthenticationRequest{
			UserID: "alice", Method: "ascii", Password: passCanary,
		}, callOpts{})
		if authn.Code != "" {
			t.Fatalf("%s authentication.test: %s %s", w.Name, authn.Code, authn.Raw)
		}
		rad := invoke(t, w, operations.IDRadiusAccessTest, operations.RadiusAccessTestRequest{
			UserID: "alice", Method: operations.RadiusAuthMethod{Type: "pap", Password: passCanary},
		}, callOpts{})
		if rad.Code != "" {
			t.Fatalf("%s radius.access.test: %s %s", w.Name, rad.Code, rad.Raw)
		}
		created := invoke(t, w, operations.IDTokensCreate, operations.CreateTokenRequest{
			ID: "canary", Name: "canary", Scopes: []string{"state:read"},
		}, callOpts{})
		if created.Code != "" {
			t.Fatalf("%s tokens.create: %s %s", w.Name, created.Code, created.Raw)
		}
		once := tokenValue(created.Data)
		if once == "" {
			t.Fatalf("%s missing one-time token", w.Name)
		}
		if w.Name != "direct" {
			deny := invoke(t, w, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{Token: tokenCanary})
			if deny.Code != "unauthenticated" {
				t.Fatalf("%s invalid token code=%q", w.Name, deny.Code)
			}
			if strings.Contains(string(deny.Raw), tokenCanary) {
				t.Fatalf("%s invalid token echoed: %s", w.Name, deny.Raw)
			}
		}
		for _, rd := range reads {
			out := invoke(t, w, rd.id, rd.req, callOpts{})
			blob := canonicalJSON(out.Data) + string(out.Raw)
			if strings.Contains(blob, passCanary) || strings.Contains(blob, once) || strings.Contains(blob, w.Token) {
				t.Fatalf("%s %s leaked canary: %s", w.Name, rd.id, blob)
			}
			if strings.Contains(blob, "/run/secrets/alice-login") && strings.Contains(blob, "verifier") {
				t.Fatalf("%s %s leaked secret ref: %s", w.Name, rd.id, blob)
			}
		}
	}
}

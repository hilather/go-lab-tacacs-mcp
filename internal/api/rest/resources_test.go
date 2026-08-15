package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func TestUsersGroupsClientsREST(t *testing.T) {
	t.Parallel()
	h := restHarness(t)

	list := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/users", h.Token, nil, nil)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(list.Body)
		t.Fatalf("list users=%d %s", list.StatusCode, b)
	}
	var users struct {
		Data operations.UserList `json:"data"`
	}
	if err := json.NewDecoder(list.Body).Decode(&users); err != nil {
		t.Fatal(err)
	}
	if len(users.Data.Items) != 1 || users.Data.Items[0].ID != "alice" {
		t.Fatalf("users=%+v", users.Data)
	}

	body := []byte(`{"id":"bob","enabled":false,"display_name":"Bob"}`)
	created := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/users", h.Token, body, nil)
	defer created.Body.Close()
	if created.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(created.Body)
		t.Fatalf("create user=%d %s", created.StatusCode, b)
	}
	etag := created.Header.Get("ETag")
	var createdEnv struct {
		Revision uint64          `json:"revision"`
		Data     operations.User `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&createdEnv); err != nil {
		t.Fatal(err)
	}
	if createdEnv.Revision == 0 || createdEnv.Revision != uint64(createdEnv.Data.EffectiveRevision) {
		t.Fatalf("create envelope=%+v etag=%s", createdEnv, etag)
	}
	if !strings.Contains(etag, "revision-") {
		t.Fatalf("etag=%q", etag)
	}

	patch := doAuth(t, http.MethodPatch, h.HTTP.URL+"/api/v1/users/bob", h.Token, []byte(`{"display_name":"Bobby"}`), map[string]string{"If-Match": etag})
	defer patch.Body.Close()
	if patch.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patch.Body)
		t.Fatalf("patch user=%d %s", patch.StatusCode, b)
	}

	del := doAuth(t, http.MethodDelete, h.HTTP.URL+"/api/v1/users/bob", h.Token, nil, nil)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(del.Body)
		t.Fatalf("delete user=%d %s", del.StatusCode, b)
	}

	groups := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/groups", h.Token, nil, nil)
	defer groups.Body.Close()
	if groups.StatusCode != http.StatusOK {
		t.Fatalf("groups=%d", groups.StatusCode)
	}

	clients := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/clients", h.Token, nil, nil)
	defer clients.Body.Close()
	raw, _ := io.ReadAll(clients.Body)
	if clients.StatusCode != http.StatusOK {
		t.Fatalf("clients=%d %s", clients.StatusCode, raw)
	}
	if strings.Contains(string(raw), "shared_secret\":{\"file\"") {
		t.Fatal("shared secret ref leaked")
	}
}

func TestConfigAndAuthTestREST(t *testing.T) {
	t.Parallel()
	h := restHarness(t)

	eff := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/config/effective", h.Token, nil, nil)
	defer eff.Body.Close()
	if eff.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(eff.Body)
		t.Fatalf("effective=%d %s", eff.StatusCode, b)
	}

	exp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/config/export", h.Token, nil, nil)
	defer exp.Body.Close()
	if exp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(exp.Body)
		t.Fatalf("export=%d %s", exp.StatusCode, b)
	}
	var env struct {
		Data operations.ExportConfigResult `json:"data"`
	}
	if err := json.NewDecoder(exp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(env.Data.YAML, "redacted: true") {
		t.Fatalf("export yaml=%s", env.Data.YAML)
	}
	if !strings.HasPrefix(env.Data.YAML, "schema_version: 1\n") || env.Data.Normalized {
		t.Fatalf("v1 source exported as v2 without normalize: %+v\n%s", env.Data, env.Data.YAML)
	}

	norm := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/config/export?normalize=true", h.Token, nil, nil)
	defer norm.Body.Close()
	if norm.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(norm.Body)
		t.Fatalf("export normalize=%d %s", norm.StatusCode, b)
	}
	var normEnv struct {
		Data operations.ExportConfigResult `json:"data"`
	}
	if err := json.NewDecoder(norm.Body).Decode(&normEnv); err != nil {
		t.Fatal(err)
	}
	if !normEnv.Data.Normalized || !strings.HasPrefix(normEnv.Data.YAML, "schema_version: 2\n") {
		t.Fatalf("normalize export=%+v", normEnv.Data)
	}

	val := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/config/validate", h.Token, []byte(`{"yaml":"schema_version: 1\n"}`), nil)
	defer val.Body.Close()
	if val.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(val.Body)
		t.Fatalf("validate=%d %s", val.StatusCode, b)
	}

	authn := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/authentication/test", h.Token, []byte(`{"user_id":"alice","method":"ascii","password":"unit-test-rest-auth-canary-zz7"}`), nil)
	defer authn.Body.Close()
	body, _ := io.ReadAll(authn.Body)
	if authn.StatusCode != http.StatusOK {
		t.Fatalf("auth test=%d %s", authn.StatusCode, body)
	}
	if strings.Contains(string(body), "unit-test-rest-auth-canary-zz7") {
		t.Fatal("password leaked from authentication.test")
	}

	rad := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/radius/access:test", h.Token, []byte(`{"user_id":"alice","method":{"type":"pap","password":"unit-test-rest-radius-canary-zz8"}}`), nil)
	defer rad.Body.Close()
	radBody, _ := io.ReadAll(rad.Body)
	if rad.StatusCode != http.StatusOK {
		t.Fatalf("radius access test=%d %s", rad.StatusCode, radBody)
	}
	if strings.Contains(string(radBody), "unit-test-rest-radius-canary-zz8") {
		t.Fatal("password leaked from radius.access.test")
	}
	attrs := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/radius/attributes", h.Token, nil, nil)
	defer attrs.Body.Close()
	if attrs.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(attrs.Body)
		t.Fatalf("radius attributes=%d %s", attrs.StatusCode, b)
	}

	reload := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/config/reload", h.Token, nil, nil)
	defer reload.Body.Close()
	if reload.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(reload.Body)
		t.Fatalf("reload=%d %s", reload.StatusCode, b)
	}

	reset := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/runtime/reset", h.Token, nil, nil)
	defer reset.Body.Close()
	if reset.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(reset.Body)
		t.Fatalf("reset=%d %s", reset.StatusCode, b)
	}
}

func TestOptionalSecretUnknownFieldRejected(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/users", h.Token, []byte(`{"id":"eve","enabled":false,"login":{"file":"/run/secrets/x","value":"cleartext"}}`), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "invalid_argument" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestUsersWriteRequiresScope(t *testing.T) {
	t.Parallel()
	h := restHarnessScopes(t, []string{"state:read"})
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/users", h.Token, []byte(`{"id":"x","enabled":false}`), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
}

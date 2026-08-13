package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func TestTokenCreateListRevoke(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	body := []byte(`{"id":"ci","name":"CI","scopes":["state:read"]}`)
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/tokens", h.Token, body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create=%d %s", resp.StatusCode, b)
	}
	var created struct {
		Data operations.CreatedToken `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Data.Token == "" || created.Data.ID != "ci" {
		t.Fatalf("created=%+v", created.Data)
	}

	list := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/tokens", h.Token, nil, nil)
	defer list.Body.Close()
	raw, _ := io.ReadAll(list.Body)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list=%d %s", list.StatusCode, raw)
	}
	if strings.Contains(string(raw), created.Data.Token) {
		t.Fatal("one-time token leaked from list")
	}

	del := doAuth(t, http.MethodDelete, h.HTTP.URL+"/api/v1/tokens/ci", h.Token, nil, nil)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(del.Body)
		t.Fatalf("revoke=%d %s", del.StatusCode, b)
	}

	again := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/tokens", h.Token, nil, nil)
	defer again.Body.Close()
	var env struct {
		Data operations.TokenList `json:"data"`
	}
	if err := json.NewDecoder(again.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	for _, tok := range env.Data.Items {
		if tok.ID == "ci" {
			t.Fatal("revoked token still listed")
		}
	}
}

func TestTokenCreateRequiresManageScope(t *testing.T) {
	t.Parallel()
	h := restHarnessScopes(t, []string{"state:write", "state:read"})
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/tokens", h.Token, []byte(`{"id":"x","scopes":["state:read"]}`), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
}

package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRESTCanaries(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	const canary = "unit-test-rest-secret-canary-zz42"
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/status", "not-a-token-"+canary, nil, nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), canary) || strings.Contains(string(body), h.Token) {
		t.Fatalf("secret leaked in problem: %s", body)
	}

	created := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/tokens", h.Token, []byte(`{"id":"canary","scopes":["state:read"]}`), nil)
	defer created.Body.Close()
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Token == "" {
		t.Fatal("missing one-time token")
	}
	list := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/tokens", h.Token, nil, nil)
	defer list.Body.Close()
	listed, _ := io.ReadAll(list.Body)
	if strings.Contains(string(listed), env.Data.Token) {
		t.Fatal("one-time token leaked from list")
	}

	sess := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/session", h.Token, nil, nil)
	defer sess.Body.Close()
	sbody, _ := io.ReadAll(sess.Body)
	for _, c := range sess.Cookies() {
		if c.Name == "taclab_session" && strings.Contains(string(sbody), c.Value) {
			t.Fatal("session cookie in JSON")
		}
	}
}

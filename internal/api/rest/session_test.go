package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func TestSessionCookieAndCSRFRequired(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/session", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
	var env struct {
		Data operations.Session `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Data.CSRFToken == "" || env.Data.CookieSecure {
		t.Fatalf("sess=%+v", env.Data)
	}
	raw, _ := json.Marshal(env.Data)
	if strings.Contains(strings.ToLower(string(raw)), "cookie") && strings.Contains(string(raw), "taclab_session=") {
		t.Fatal("session cookie leaked")
	}

	var sessionCookie, csrfCookie string
	for _, c := range resp.Cookies() {
		switch c.Name {
		case auth.CookieName:
			sessionCookie = c.Value
			if !c.HttpOnly || c.Secure {
				t.Fatalf("session cookie flags=%+v", c)
			}
		case auth.CSRFCookieName:
			csrfCookie = c.Value
			if c.HttpOnly {
				t.Fatal("csrf cookie must not be HttpOnly")
			}
		}
	}
	if sessionCookie == "" || csrfCookie == "" {
		t.Fatal("missing set-cookie")
	}

	// Cookie mutation without CSRF is 403.
	req, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/api/v1/tokens", strings.NewReader(`{"id":"x","scopes":["state:read"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	noCSRF, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(noCSRF.Body)
		t.Fatalf("no csrf status=%d %s", noCSRF.StatusCode, b)
	}

	req2, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/api/v1/tokens", strings.NewReader(`{"id":"from-cookie","scopes":["state:read"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set(auth.CSRFHeader, env.Data.CSRFToken)
	req2.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	ok, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(ok.Body)
		t.Fatalf("csrf status=%d %s", ok.StatusCode, b)
	}

	del, err := http.NewRequest(http.MethodDelete, h.HTTP.URL+"/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	del.Header.Set(auth.CSRFHeader, env.Data.CSRFToken)
	del.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	dresp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dresp.Body)
		t.Fatalf("logout=%d %s", dresp.StatusCode, b)
	}

	again, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	again.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	aresp, err := http.DefaultClient.Do(again)
	if err != nil {
		t.Fatal(err)
	}
	defer aresp.Body.Close()
	if aresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout status=%d", aresp.StatusCode)
	}
}

func TestSessionCreateRequiresBearer(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp, err := http.Post(h.HTTP.URL+"/api/v1/session", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestCookieReadWithoutCSRF(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/session", h.Token, nil, nil)
	defer resp.Body.Close()
	var sessionCookie string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			sessionCookie = c.Value
		}
	}
	req, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(got.Body)
		t.Fatalf("read without csrf=%d %s", got.StatusCode, b)
	}
}

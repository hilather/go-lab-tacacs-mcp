package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

	// Both cookies without X-CSRF-Token must not pass (browsers always send cookies).
	reqCookieOnly, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/api/v1/tokens", strings.NewReader(`{"id":"x","scopes":["state:read"]}`))
	if err != nil {
		t.Fatal(err)
	}
	reqCookieOnly.Header.Set("Content-Type", "application/json")
	reqCookieOnly.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie})
	reqCookieOnly.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfCookie})
	cookieOnly, err := http.DefaultClient.Do(reqCookieOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer cookieOnly.Body.Close()
	if cookieOnly.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(cookieOnly.Body)
		t.Fatalf("csrf cookie without header status=%d %s", cookieOnly.StatusCode, b)
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

func TestSessionGetCookieWhoami(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	created := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/session", h.Token, nil, nil)
	defer created.Body.Close()
	if created.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(created.Body)
		t.Fatalf("create status=%d %s", created.StatusCode, b)
	}
	var createEnv struct {
		Data operations.Session `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&createEnv); err != nil {
		t.Fatal(err)
	}
	var sessionCookie string
	for _, c := range created.Cookies() {
		if c.Name == auth.CookieName {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("missing session cookie")
	}

	req, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/session", nil)
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
		t.Fatalf("get status=%d %s", got.StatusCode, b)
	}
	if len(got.Cookies()) != 0 {
		t.Fatalf("get must not Set-Cookie: %+v", got.Cookies())
	}
	var env struct {
		Data operations.Session `json:"data"`
	}
	raw, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), sessionCookie) || strings.Contains(string(raw), "taclab_session=") {
		t.Fatal("session cookie leaked")
	}
	if env.Data.TokenID != "lab" {
		t.Fatalf("token_id=%q", env.Data.TokenID)
	}
	if env.Data.CSRFToken != "" {
		t.Fatalf("csrf_token should be empty on get, got %q", env.Data.CSRFToken)
	}
	if env.Data.ExpiresAt.IsZero() {
		t.Fatal("expires_at required")
	}
	foundManage := false
	for _, sc := range env.Data.Scopes {
		if sc == "tokens:manage" {
			foundManage = true
		}
	}
	if !foundManage {
		t.Fatalf("scopes=%v want tokens:manage", env.Data.Scopes)
	}

	bearerOnly, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	bearerOnly.Header.Set("Authorization", "Bearer "+h.Token)
	bresp, err := http.DefaultClient.Do(bearerOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer bresp.Body.Close()
	if bresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer-only get status=%d", bresp.StatusCode)
	}

	anon, err := http.Get(h.HTTP.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	defer anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous get status=%d", anon.StatusCode)
	}

	del, err := http.NewRequest(http.MethodDelete, h.HTTP.URL+"/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	del.Header.Set(auth.CSRFHeader, createEnv.Data.CSRFToken)
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
	again, err := http.NewRequest(http.MethodGet, h.HTTP.URL+"/api/v1/session", nil)
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
		t.Fatalf("after logout get status=%d", aresp.StatusCode)
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

func TestDecodeOptionalJSONEmptyUnknownLength(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	var dest operations.CreateSessionRequest
	if err := decodeOptionalJSON(req, &dest, 1024); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCreateUnknownLengthEmptyBody(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	req, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/api/v1/session", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
}

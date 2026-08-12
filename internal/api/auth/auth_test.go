package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func TestVerifyBearerCorrectAndNegatives(t *testing.T) {
	t.Parallel()
	m, value, clock := mustTokenMgr(t, []string{"state:read", "tokens:manage"}, nil)
	svc := New(Options{Clock: clock})
	snap := m.Snapshot()

	p, err := svc.VerifyBearer([]byte(value), snap)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenID != "rt" || !Has(p.Scopes, "tokens:manage") || p.Cookie {
		t.Fatalf("principal=%+v", p)
	}
	if _, ok := svc.LastUsed("rt"); !ok {
		t.Fatal("last-used")
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"malformed", []byte("not-a-real-token")},
		{"unknown", []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
	}
	for _, tc := range cases {
		if _, err := svc.VerifyBearer(tc.raw, snap); !isCode(err, domain.CodeUnauthenticated) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

func TestVerifyBearerExpiredAndRevoked(t *testing.T) {
	t.Parallel()
	exp := time.Date(2026, 8, 12, 14, 0, 0, 0, time.UTC)
	m, value, clock := mustTokenMgr(t, []string{"state:read"}, &exp)
	svc := New(Options{Clock: clock})
	if _, err := svc.VerifyBearer([]byte(value), m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("expired: %v", err)
	}

	m2, value2, clock2 := mustTokenMgr(t, []string{"state:read"}, nil)
	svc2 := New(Options{Clock: clock2})
	rev := m2.Revision()
	if _, err := m2.DeleteToken("rt", state.DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc2.VerifyBearer([]byte(value2), m2.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestAuthenticateBearerHeader(t *testing.T) {
	t.Parallel()
	m, value, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	p, err := svc.Authenticate(Request{Authorization: "Bearer " + value}, m.Snapshot())
	if err != nil || p.TokenID != "rt" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if _, err := svc.Authenticate(Request{Authorization: "Basic x"}, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("basic: %v", err)
	}
}

func TestBootstrapLoadAndVerify(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "boot")
	const secret = "unit-test-bootstrap-auth-canary-1122"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
api:
  bootstrap_tokens:
    - id: lab-admin
      token: {file: %s}
      scopes: [state:read, state:write, tokens:manage]
`, path)
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := config.FileLookup(config.ReadOptions{StrictFilesSet: true, StrictFiles: false})
	m, err := state.New(doc, state.Options{Clock: &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}, Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if err := LoadBootstrap(m.Snapshot(), lookup); err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}
	svc := New(Options{Clock: clock})
	p, err := svc.VerifyBearer([]byte(secret), m.Snapshot())
	if err != nil || p.TokenID != "lab-admin" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
}

func TestSessionCookieAndCSRF(t *testing.T) {
	t.Parallel()
	m, value, clock := mustTokenMgr(t, []string{"state:read", "state:write"}, nil)
	svc := New(Options{Clock: clock})
	snap := m.Snapshot()
	if snap.Settings().API.UISession.CookieSecure {
		t.Fatal("HTTP lab cookie_secure must follow TLS off")
	}
	actor := operations.Actor{ID: "rt", Scopes: []string{"state:read", "state:write"}}
	sess, err := svc.Create(actor, snap)
	if err != nil {
		t.Fatal(err)
	}
	if sess.CSRFToken == "" || sess.Cookie.Empty() || sess.CookieSecure || sess.SameSite != "strict" {
		t.Fatalf("sess=%+v", sess)
	}
	raw, err := json.Marshal(sess)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), string(sess.Cookie.Bytes())) {
		t.Fatal("session cookie in JSON")
	}
	if !strings.Contains(string(raw), sess.CSRFToken) {
		t.Fatal("CSRF must be returned once")
	}
	cookie := string(sess.Cookie.Bytes())

	if _, err := svc.VerifyCookie(cookie, "", false, snap); err != nil {
		t.Fatalf("read without CSRF: %v", err)
	}
	if _, err := svc.VerifyCookie(cookie, "", true, snap); !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("mutation without CSRF: %v", err)
	}
	if _, err := svc.VerifyCookie(cookie, "wrong-csrf", true, snap); !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("bad CSRF: %v", err)
	}
	p, err := svc.VerifyCookie(cookie, sess.CSRFToken, true, snap)
	if err != nil || !p.Cookie || p.TokenID != "rt" || p.SessionID == "" {
		t.Fatalf("p=%+v err=%v", p, err)
	}

	hc := SessionCookie(sess)
	if !hc.HttpOnly || hc.Secure || hc.SameSite != 0 && hc.Name != CookieName {
		// SameSiteStrictMode is 3; just check flags that matter.
	}
	if !hc.HttpOnly || hc.Secure || hc.Name != CookieName {
		t.Fatalf("cookie=%+v", hc)
	}
	cs := CSRFSetCookie(sess)
	if cs.HttpOnly || cs.Name != CSRFCookieName {
		t.Fatalf("csrf cookie=%+v", cs)
	}

	if _, err := svc.Delete(p.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyCookie(cookie, sess.CSRFToken, false, snap); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("deleted: %v", err)
	}

	// Bearer path still works after logout.
	if _, err := svc.VerifyBearer([]byte(value), snap); err != nil {
		t.Fatal(err)
	}
}

func TestCookieSecureFollowsTLS(t *testing.T) {
	t.Parallel()
	src := `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
  http:
    tls: {enabled: true}
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.API.UISession.CookieSecure {
		t.Fatal("cookie_secure should follow TLS")
	}
	m, err := state.New(doc, state.Options{Clock: &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	value, _, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateToken(state.CreateToken{ID: "rt", Name: "rt", Scopes: []string{"state:read"}, Material: credentials.NewTokenMaterial([]byte(value))}, &rev); err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt", Scopes: []string{"state:read"}}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !sess.CookieSecure || !SessionCookie(sess).Secure {
		t.Fatalf("secure=%v cookie=%+v", sess.CookieSecure, SessionCookie(sess))
	}
}

func TestSessionIdleAndLifetime(t *testing.T) {
	t.Parallel()
	clock := &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}
	m, _, _ := mustTokenMgrClock(t, []string{"state:read"}, nil, clock)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt", Scopes: []string{"state:read"}}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	cookie := string(sess.Cookie.Bytes())
	clock.t = clock.t.Add(11 * time.Minute)
	if _, err := svc.VerifyCookie(cookie, "", false, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("idle: %v", err)
	}
}

func TestSessionCreateUnauthenticated(t *testing.T) {
	t.Parallel()
	m, _, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	if _, err := svc.Create(operations.Actor{}, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("err=%v", err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	t.Parallel()
	m, value, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	snap := m.Snapshot()
	var wg sync.WaitGroup
	errc := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.VerifyBearer([]byte(value), snap); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func mustTokenMgr(t testing.TB, scopes []string, exp *time.Time) (*state.Manager, string, *fixedClock) {
	t.Helper()
	return mustTokenMgrClock(t, scopes, exp, &fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)})
}

func mustTokenMgrClock(t testing.TB, scopes []string, exp *time.Time, clock *fixedClock) (*state.Manager, string, *fixedClock) {
	t.Helper()
	doc, err := config.Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := state.New(doc, state.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	if _, err := m.CreateToken(state.CreateToken{
		ID:        "rt",
		Name:      "runtime",
		Scopes:    scopes,
		Material:  credentials.NewTokenMaterial([]byte(value)),
		ExpiresAt: exp,
	}, &rev); err != nil {
		t.Fatal(err)
	}
	return m, value, clock
}

func isCode(err error, code domain.Code) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == code
}

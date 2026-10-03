package auth

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestReviewRevokedCookieCannotRevive(t *testing.T) {
	m, _, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.DeleteToken("rt", state.DeleteOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateToken(state.CreateToken{ID: "rt", Name: "replacement", Scopes: []string{"tokens:manage"}, Material: credentials.NewTokenMaterial([]byte("replacement-value"))}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := svc.VerifyCookie(string(sess.Cookie.Bytes()), sess.CSRFToken, true, m.Snapshot())
	if !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("revoked cookie revived: scopes=%v err=%v", p.Scopes, err)
	}
}
func TestSessionRejectsRuntimeTokenRotation(t *testing.T) {
	m, _, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateToken(state.CreateToken{ID: "rt", Override: true, Scopes: []string{"tokens:manage"}, Material: credentials.NewTokenMaterial([]byte("replacement"))}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("rotated token accepted cookie: %v", err)
	}
}

func TestSessionSurvivesUnrelatedMutation(t *testing.T) {
	m, _, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateUser(state.CreateUser{ID: "other"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, m.Snapshot()); err != nil {
		t.Fatalf("unrelated mutation invalidated session: %v", err)
	}
}

func TestSessionRejectsSameMaterialRecreatedToken(t *testing.T) {
	m, value, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.DeleteToken("rt", state.DeleteOptions{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = m.CreateToken(state.CreateToken{ID: "rt", Scopes: []string{"tokens:manage"}, Material: credentials.NewTokenMaterial([]byte(value))}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("same-material replacement revived cookie: %v", err)
	}
}

func TestForgetInvalidatesSessions(t *testing.T) {
	m, _, clock := mustTokenMgr(t, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	svc.Forget("rt")
	if _, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("forgotten session authenticated: %v", err)
	}
}

func TestSessionRejectsBaselineGrantChanges(t *testing.T) {
	for _, kind := range []string{"scopes", "expiry", "restore"} {
		t.Run(kind, func(t *testing.T) {
			_, value, clock := mustTokenMgr(t, []string{"state:read"}, nil)
			doc, err := config.Parse([]byte("schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\n"))
			if err != nil {
				t.Fatal(err)
			}
			doc.API.BootstrapTokens = []config.BootstrapToken{{ID: "rt", Token: config.SecretRef{File: "/review/token", Purpose: credentials.PurposeAPIBearerToken}, Scopes: []string{"state:read"}}}
			m, err := state.New(doc, state.Options{Clock: clock, Secrets: func(config.SecretRef) ([]byte, error) { return []byte(value), nil }})
			if err != nil {
				t.Fatal(err)
			}
			svc := New(Options{Clock: clock})
			sess, err := svc.Create(operations.Actor{ID: "rt"}, m.Snapshot())
			if err != nil {
				t.Fatal(err)
			}
			if kind == "restore" {
				if _, err = m.CreateToken(state.CreateToken{ID: "rt", Override: true, Scopes: []string{"state:read"}, Material: credentials.NewTokenMaterial([]byte(value))}, nil); err != nil {
					t.Fatal(err)
				}
				if _, err = m.Reset(nil); err != nil {
					t.Fatal(err)
				}
			} else {
				if kind == "scopes" {
					doc.API.BootstrapTokens[0].Scopes = []string{"tokens:manage"}
				} else {
					expiry := clock.Now().Add(60 * 60 * 1e9)
					doc.API.BootstrapTokens[0].ExpiresAt = &expiry
				}
				if _, err = m.Reload(doc, nil); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
				t.Fatalf("%s preserved old grant: %v", kind, err)
			}
		})
	}
}

func TestStreamRevalidation(t *testing.T) {
	for _, kind := range []string{"expiry", "recreate", "grant-loss", "cookie-idle", "cookie-delete"} {
		t.Run(kind, func(t *testing.T) {
			m, value, clock := mustTokenMgr(t, []string{"events:read", "events:sensitive"}, nil)
			svc := New(Options{Clock: clock})
			snap := m.Snapshot()
			p, err := svc.VerifyBearer([]byte(value), snap)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "cookie-idle" || kind == "cookie-delete" {
				sess, err := svc.Create(p.Actor(), snap)
				if err != nil {
					t.Fatal(err)
				}
				p, err = svc.VerifyCookie(string(sess.Cookie.Bytes()), "", false, snap)
				if err != nil {
					t.Fatal(err)
				}
			}
			generation := snap.TokenGeneration(p.TokenID)
			if _, err = svc.Revalidate(p.Actor(), generation, snap); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expiry":
				exp := clock.Now().Add(time.Minute)
				if _, err = m.CreateToken(state.CreateToken{ID: "rt", Override: true, Scopes: p.Scopes, Material: credentials.NewTokenMaterial([]byte(value)), ExpiresAt: &exp}, nil); err != nil {
					t.Fatal(err)
				}
				snap = m.Snapshot()
				generation = snap.TokenGeneration("rt")
				clock.t = exp
			case "recreate":
				if _, err = m.DeleteToken("rt", state.DeleteOptions{}, nil); err != nil {
					t.Fatal(err)
				}
				if _, err = m.CreateToken(state.CreateToken{ID: "rt", Scopes: p.Scopes, Material: credentials.NewTokenMaterial([]byte(value))}, nil); err != nil {
					t.Fatal(err)
				}
			case "grant-loss":
				if _, err = m.CreateToken(state.CreateToken{ID: "rt", Override: true, Scopes: []string{"state:read"}, Material: credentials.NewTokenMaterial([]byte(value))}, nil); err != nil {
					t.Fatal(err)
				}
			case "cookie-idle":
				idle := snap.Settings().API.UISession.IdleTimeout
				if idle <= 0 {
					t.Fatal("fixture idle timeout missing")
				}
				clock.t = clock.Now().Add(idle / 2)
				if _, err = svc.Revalidate(p.Actor(), generation, snap); err != nil {
					t.Fatal(err)
				}
				clock.t = clock.Now().Add(idle / 2)
			case "cookie-delete":
				if _, err = svc.Delete(p.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = svc.Revalidate(p.Actor(), generation, m.Snapshot()); !isCode(err, domain.CodeUnauthenticated) {
				t.Fatalf("%s accepted: %v", kind, err)
			}
		})
	}
}

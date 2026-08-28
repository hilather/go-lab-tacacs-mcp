package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

var tokenAdmin = Actor{ID: "admin", Scopes: []string{"tokens:manage", "state:read"}}

func TestTokenCreateListRevoke(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	res, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
		Actor: tokenAdmin,
		Request: CreateTokenRequest{
			ID:     "ci",
			Name:   "CI",
			Scopes: []string{"state:read", "events:read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, ok := res.Data.(CreatedToken)
	if !ok || created.Token == "" || created.ID != "ci" {
		t.Fatalf("created=%T %+v", res.Data, res.Data)
	}
	if created.Source != domain.SourceRuntime {
		t.Fatalf("source=%s", created.Source)
	}
	if created.RevisionCreated == 0 || created.RevisionUpdated == 0 || created.DisplayName == "" {
		t.Fatalf("envelope missing: %+v", created.TokenView)
	}
	raw, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), created.Token) {
		t.Fatal("one-time token missing from create JSON")
	}

	snap := m.Snapshot()
	if _, err := snap.AuthenticateToken([]byte(created.Token), snap.CompiledAt); err != nil {
		t.Fatal(err)
	}

	list, err := reg.Invoke(context.Background(), IDTokensList, snap, Input{Actor: tokenAdmin})
	if err != nil {
		t.Fatal(err)
	}
	tl := list.Data.(TokenList)
	if len(tl.Items) != 1 || tl.Items[0].ID != "ci" {
		t.Fatalf("list=%+v", tl)
	}
	listed, err := json.Marshal(tl)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(listed), created.Token) {
		t.Fatal("token value leaked from list")
	}

	rev := snap.Revision
	_, err = reg.Invoke(context.Background(), IDTokensRevoke, snap, Input{
		Actor:            tokenAdmin,
		ExpectedRevision: &rev,
		Request:          RevokeTokenRequest{ID: "ci"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Snapshot().AuthenticateToken([]byte(created.Token), snap.CompiledAt); !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("revoked still works: %v", err)
	}
}

func TestTokenCreateRequiresManageScope(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	_, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
		Actor:   Actor{ID: "w", Scopes: []string{"state:write"}},
		Request: CreateTokenRequest{Scopes: []string{"state:read"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("err=%v", err)
	}
	_, err = reg.Invoke(context.Background(), IDTokensList, m.Snapshot(), Input{
		Actor: Actor{ID: "w", Scopes: []string{"state:write"}},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("list err=%v", err)
	}
}

func TestTokenCreateRejectsUnknownScope(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	_, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
		Actor:   tokenAdmin,
		Request: CreateTokenRequest{Scopes: []string{"admin"}},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestTokenCreateCanary(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	res, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
		Actor:   tokenAdmin,
		Request: CreateTokenRequest{ID: "canary", Scopes: []string{"state:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	created := res.Data.(CreatedToken)
	list, err := reg.Invoke(context.Background(), IDTokensList, m.Snapshot(), Input{Actor: tokenAdmin})
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", list.Data)
	if strings.Contains(dump, created.Token) {
		t.Fatal("list dump leaked bearer")
	}
}

func TestTokenRevokeNotFound(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	_, err := reg.Invoke(context.Background(), IDTokensRevoke, m.Snapshot(), Input{
		Actor:   tokenAdmin,
		Request: RevokeTokenRequest{ID: "missing"},
	})
	if !isCode(err, domain.CodeNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestTokenCreateRevisionMismatch(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	stale := domain.Revision(99)
	_, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
		Actor:            tokenAdmin,
		ExpectedRevision: &stale,
		Request:          CreateTokenRequest{Scopes: []string{"state:read"}},
	})
	if !isCode(err, domain.CodeRevisionMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestTokenOpsConcurrent(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustTokenRegistry(t, m)
	var wg sync.WaitGroup
	errc := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		id := fmt.Sprintf("t%d", i)
		go func() {
			defer wg.Done()
			_, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{
				Actor:   tokenAdmin,
				Request: CreateTokenRequest{ID: id, Scopes: []string{"state:read"}},
			})
			if err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
	list, err := reg.Invoke(context.Background(), IDTokensList, m.Snapshot(), Input{Actor: tokenAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(list.Data.(TokenList).Items); n != 8 {
		t.Fatalf("items=%d", n)
	}
}

func TestSessionOperations(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	value, _, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateToken(state.CreateToken{
		ID:       "sess",
		Name:     "sess",
		Scopes:   []string{"state:read"},
		Material: credentials.NewTokenMaterial([]byte(value)),
	}, &rev); err != nil {
		t.Fatal(err)
	}
	sessions := &memSessions{byID: map[string]Session{}}
	reg := mustTokenRegistrySessions(t, m, sessions)
	res, err := reg.Invoke(context.Background(), IDSessionCreate, m.Snapshot(), Input{
		Actor: Actor{ID: "sess", Scopes: []string{"state:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess := res.Data.(Session)
	if sess.CSRFToken == "" || sess.TokenID != "sess" {
		t.Fatalf("sess=%+v", sess)
	}
	_, err = reg.Invoke(context.Background(), IDSessionDelete, m.Snapshot(), Input{
		Actor:   Actor{ID: "sess", SessionID: "sid-1"},
		Request: DeleteSessionRequest{},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionDeleteRequiresPrincipal(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	sessions := &memSessions{byID: map[string]Session{"sid-1": {TokenID: "sess"}}}
	reg := mustTokenRegistrySessions(t, m, sessions)
	_, err := reg.Invoke(context.Background(), IDSessionDelete, m.Snapshot(), Input{
		Request: DeleteSessionRequest{SessionID: "sid-1"},
	})
	if !isCode(err, domain.CodeUnauthenticated) {
		t.Fatalf("public logout: %v", err)
	}
	if _, ok := sessions.byID["sid-1"]; !ok {
		t.Fatal("session deleted without principal")
	}
	_, err = reg.Invoke(context.Background(), IDSessionDelete, m.Snapshot(), Input{
		Actor:   Actor{ID: "sess", SessionID: "sid-1"},
		Request: DeleteSessionRequest{SessionID: "other"},
	})
	if !isCode(err, domain.CodePermissionDenied) {
		t.Fatalf("body mismatch: %v", err)
	}
	if created := sessions.byID["sid-1"]; created.TokenID != "sess" {
		t.Fatal("mismatch deleted session")
	}
}

func mustTokenRegistry(t *testing.T, m *state.Manager) *Registry {
	t.Helper()
	return mustTokenRegistrySessions(t, m, nil)
}

func mustTokenRegistrySessions(t *testing.T, m *state.Manager, sess SessionService) *Registry {
	t.Helper()
	reg, err := New(mustSpec(t), Deps{
		Build:    BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-12T00:00:00Z"},
		State:    m,
		Sessions: sess,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

type memSessions struct {
	byID map[string]Session
}

func (m *memSessions) Create(actor Actor, snap *state.Snapshot) (Session, error) {
	s := Session{
		TokenID:    actor.ID,
		Scopes:     append([]string(nil), actor.Scopes...),
		ExpiresAt:  time.Date(2026, 8, 12, 15, 30, 0, 0, time.UTC),
		CSRFToken:  "unit-test-csrf",
		CookieName: "taclab_session",
		SameSite:   "strict",
		CookiePath: "/",
		Revision:   snap.Revision,
		Cookie:     credentials.NewSessionCookie([]byte("unit-test-session-cookie")),
	}
	m.byID["sid-1"] = s
	return s, nil
}

func (m *memSessions) Get(sessionID string, snap *state.Snapshot) (Session, error) {
	s, ok := m.byID[sessionID]
	if !ok {
		return Session{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	if snap != nil {
		s.Revision = snap.Revision
	}
	s.CSRFToken = ""
	return s, nil
}

func (m *memSessions) Delete(sessionID string) (DeleteResult, error) {
	if _, ok := m.byID[sessionID]; !ok {
		return DeleteResult{}, domain.NewError(domain.CodeNotFound, "session not found")
	}
	delete(m.byID, sessionID)
	return DeleteResult{ID: sessionID}, nil
}

var _ = config.SchemaVersion

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

type incarnationBody struct {
	io.Reader
	once   sync.Once
	before func()
}

func (b *incarnationBody) Read(p []byte) (int, error) { b.once.Do(b.before); return b.Reader.Read(p) }
func (*incarnationBody) Close() error                 { return nil }

func TestSDKToolUsesAuthenticatedTokenIncarnation(t *testing.T) {
	h := mcpHarness(t)
	token, err := h.Mgr.Snapshot().AuthenticateToken([]byte(h.Token), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bodyJSON, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "taclab.users.create", "arguments": map[string]any{"id": "incarnation-user", "idempotency_key": "incarnation-key"}, "_meta": defaultMeta()}})
	body := string(bodyJSON)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Body = &incarnationBody{Reader: strings.NewReader(body), before: func() {
		rev := h.Mgr.Revision()
		if _, err := h.Mgr.DeleteToken(token.ID, state.DeleteOptions{}, &rev); err != nil {
			t.Fatal(err)
		}
		rev = h.Mgr.Revision()
		if _, err := h.Mgr.CreateToken(state.CreateToken{ID: token.ID, Name: "replacement", Scopes: token.Scopes, Material: credentials.NewTokenMaterial([]byte(strings.Repeat("n", 40)))}, &rev); err != nil {
			t.Fatal(err)
		}
		_, err := h.Opts.Registry.Invoke(context.Background(), operations.IDUsersCreate, h.Mgr.Snapshot(), operations.Input{Actor: operations.Actor{ID: token.ID, Scopes: token.Scopes}, IdempotencyKey: "incarnation-key", Request: operations.CreateUserRequest{ID: "incarnation-user"}})
		if err != nil {
			t.Fatal(err)
		}
	}}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set(headerProtocolVersion, protocolVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerMethod, "tools/call")
	req.Header.Set("Mcp-Name", "taclab.users.create")
	rec := httptest.NewRecorder()
	Handler(h.Opts).ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "already_exists") {
		t.Fatalf("old authenticated request reached new incarnation replay: %s", rec.Body.String())
	}
}

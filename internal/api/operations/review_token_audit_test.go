package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

func TestTokenMutationsEmitSecretFreeAudit(t *testing.T) {
	m := mustMgr(t, smallYAML)
	ring := events.New(16, nil)
	t.Cleanup(ring.Close)
	reg, err := New(mustSpec(t), Deps{State: m, Events: ring})
	if err != nil {
		t.Fatal(err)
	}
	created, err := reg.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), Input{Actor: tokenAdmin, Request: CreateTokenRequest{ID: "audit", Scopes: []string{"state:read"}}})
	if err != nil {
		t.Fatal(err)
	}
	token := created.Data.(CreatedToken)
	if _, err = reg.Invoke(context.Background(), IDTokensRevoke, m.Snapshot(), Input{Actor: tokenAdmin, Request: RevokeTokenRequest{ID: "audit"}}); err != nil {
		t.Fatal(err)
	}
	items := ring.Read(events.Query{Limit: 16}).Items
	if len(items) != 2 || items[0].Type != "api.token.created" || items[1].Type != "api.token.revoked" {
		t.Fatalf("audit events=%+v", items)
	}
	if items[0].Revision != token.Revision || items[1].Revision != m.Revision() {
		t.Fatalf("audit revisions=%+v", items)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token.Token) {
		t.Fatal("token leaked to audit")
	}
	before := len(items)
	if _, err = reg.Invoke(context.Background(), IDTokensRevoke, m.Snapshot(), Input{Actor: tokenAdmin, Request: RevokeTokenRequest{ID: "audit"}}); err == nil {
		t.Fatal("revoked missing token")
	}
	if len(ring.Read(events.Query{Limit: 16}).Items) != before {
		t.Fatal("failed mutation emitted success audit")
	}
}

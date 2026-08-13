package mcp

import (
	"strings"
	"testing"
)

func TestMCPCanaries(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	const canary = "unit-test-mcp-secret-canary-zz42"
	got := mcpRPC(t, h.HTTP, "not-a-token-"+canary, "server/discover", nil, nil)
	if strings.Contains(string(got.Raw), canary) || strings.Contains(string(got.Raw), h.Token) {
		t.Fatalf("secret leaked: %s", got.Raw)
	}

	created := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.tokens.create",
		"arguments": map[string]any{"id": "canary", "name": "canary", "scopes": []string{"state:read"}},
	}, nil)
	if created.Err != nil {
		t.Fatalf("create=%+v %s", created.Err, created.Raw)
	}
	sc, _ := created.Result["structuredContent"].(map[string]any)
	tok, _ := sc["token"].(string)
	if tok == "" {
		t.Fatal("missing one-time token")
	}
	listed := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.tokens.list",
		"arguments": map[string]any{},
	}, nil)
	if strings.Contains(string(listed.Raw), tok) {
		t.Fatal("one-time token leaked from list")
	}
	exp := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.config.export",
		"arguments": map[string]any{},
	}, nil)
	if strings.Contains(string(exp.Raw), tok) || strings.Contains(string(exp.Raw), h.Token) {
		t.Fatal("token leaked from export")
	}
}

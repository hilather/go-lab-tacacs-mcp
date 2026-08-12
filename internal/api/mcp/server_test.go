package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const mcpToken = "lab-bootstrap-token-32-bytes!!!"

func mcpHarness(t *testing.T) *httptest.Server {
	t.Helper()
	reg, err := operations.NewFromRepo(".", operations.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := config.Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: /run/secrets/sw}}
groups:
  - id: ops
    priority: 10
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
users:
  - id: alice
    group_ids: [ops]
    credentials:
      login: {verifier: {file: /run/secrets/alice}}
`))
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := state.New(doc, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.Load(&config.Document{
		API: config.API{BootstrapTokens: []config.BootstrapToken{{
			ID:     "lab",
			Token:  config.SecretRef{File: "tok", Purpose: credentials.PurposeAPIBearerToken},
			Scopes: []string{"state:read", "policy:test"},
		}}},
	}, func(config.SecretRef) ([]byte, error) { return []byte(mcpToken), nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(Options{Registry: reg, Snapshot: mgr.Snapshot, Auth: v, Version: "test"})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func TestGETAndDELETERejected(t *testing.T) {
	t.Parallel()
	ts := mcpHarness(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, err := http.NewRequest(method, ts.URL+"/mcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d", method, resp.StatusCode)
		}
	}
}

func TestMCPUnauthorized(t *testing.T) {
	t.Parallel()
	ts := mcpHarness(t)
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestMCPDiscoverAndTools(t *testing.T) {
	t.Parallel()
	ts := mcpHarness(t)
	disc := mcpRPC(t, ts, "server/discover", nil)
	if disc.StatusCode != http.StatusOK {
		t.Fatalf("discover=%d", disc.StatusCode)
	}
	if disc.Result["protocolVersion"] != protocolVersion {
		t.Fatalf("discover=%v", disc.Result)
	}

	listed := mcpRPC(t, ts, "tools/list", nil)
	tools, _ := listed.Result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools=%v", listed.Result["tools"])
	}

	st := mcpRPC(t, ts, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	})
	sc, _ := st.Result["structuredContent"].(map[string]any)
	if sc["users"] == nil {
		t.Fatalf("status=%v", st.Result)
	}

	ev := mcpRPC(t, ts, "tools/call", map[string]any{
		"name": "taclab.policy.evaluate",
		"arguments": map[string]any{
			"user_id":   "alice",
			"client_id": "sw",
			"service":   "shell",
			"cmd":       "show",
		},
	})
	tr, _ := ev.Result["structuredContent"].(map[string]any)
	if tr["evaluator"] != "command" || tr["decision"] != "permit_add" {
		t.Fatalf("trace=%v", ev.Result)
	}
}

func TestUnknownRPCMethod(t *testing.T) {
	t.Parallel()
	ts := mcpHarness(t)
	got := mcpRPC(t, ts, "no/such", nil)
	if got.StatusCode != http.StatusNotFound || got.Err == nil || got.Err.Code != -32601 {
		t.Fatalf("got status=%d err=%+v", got.StatusCode, got.Err)
	}
}

func TestForbiddenOrigin(t *testing.T) {
	t.Parallel()
	ts := mcpHarness(t)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mcpToken)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

type rpcGot struct {
	StatusCode int
	Result     map[string]any
	Err        *rpcError
}

func mcpRPC(t *testing.T, ts *httptest.Server, method string, params any) rpcGot {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mcpToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Method", method)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Result map[string]any `json:"result"`
		Error  *rpcError      `json:"error"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("body=%s err=%v", b, err)
	}
	return rpcGot{StatusCode: resp.StatusCode, Result: parsed.Result, Err: parsed.Error}
}

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type harness struct {
	HTTP  *httptest.Server
	Token string
	Mgr   *state.Manager
	Ring  *events.Ring
	Opts  Options
}

func mcpHarness(t testing.TB) *harness {
	t.Helper()
	return mcpHarnessScopes(t, []string{
		"state:read", "state:write", "policy:test", "events:read", "tokens:manage",
		"events:sensitive", "config:reload", "config:export", "runtime:reset",
	}, config.MCP{})
}

func mcpHarnessScopes(t testing.TB, scopes []string, mcpCfg config.MCP) *harness {
	t.Helper()
	yamlSrc := `
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
`
	doc, err := config.Parse([]byte(yamlSrc))
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := state.New(doc, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.New(auth.Options{})
	ring := events.New(32, nil)
	t.Cleanup(ring.Close)
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operations.NewFromRepo(".", operations.Deps{
		Build:    operations.BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-12T00:00:00Z"},
		State:    mgr,
		Sessions: svc,
		Usage:    svc,
		Events:   ring,
		Creds:    creds,
		LoadBaseline: func() (*config.Document, error) {
			return config.Parse([]byte(yamlSrc))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := credentials.IssueBearer(nil)
	if err != nil {
		t.Fatal(err)
	}
	rev := mgr.Revision()
	if _, err := mgr.CreateToken(state.CreateToken{
		ID:       "lab",
		Name:     "lab",
		Scopes:   scopes,
		Material: credentials.NewTokenMaterial([]byte(value)),
	}, &rev); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Registry:     reg,
		Snapshot:     mgr.Snapshot,
		Auth:         svc,
		Events:       ring,
		MCP:          mcpCfg,
		Version:      "test",
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	ts := httptest.NewServer(Handler(opts))
	t.Cleanup(ts.Close)
	return &harness{HTTP: ts, Token: value, Mgr: mgr, Ring: ring, Opts: opts}
}

type rpcGot struct {
	StatusCode int
	Result     map[string]any
	Err        *rpcError
	Raw        []byte
}

func defaultMeta() map[string]any {
	return map[string]any{
		metaProtocolVersion:    protocolVersion,
		metaClientCapabilities: map[string]any{},
		metaClientInfo:         map[string]string{"name": "taclab-test", "version": "test"},
	}
}

func mcpRPC(t testing.TB, ts *httptest.Server, token, method string, params map[string]any, hdr map[string]string) rpcGot {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	if _, ok := params["_meta"]; !ok {
		params["_meta"] = defaultMeta()
	}
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerProtocolVersion, protocolVersion)
	req.Header.Set(headerMethod, method)
	if name, _ := params["name"].(string); name != "" {
		req.Header.Set(headerName, name)
	}
	if uri, _ := params["uri"].(string); uri != "" {
		req.Header.Set(headerName, uri)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
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
	if len(b) > 0 && bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		if err := json.Unmarshal(b, &parsed); err != nil {
			t.Fatalf("body=%s err=%v", b, err)
		}
	}
	return rpcGot{StatusCode: resp.StatusCode, Result: parsed.Result, Err: parsed.Error, Raw: b}
}

func TestGETAndDELETERejected(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, err := http.NewRequest(method, h.HTTP.URL+"/mcp", nil)
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
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, "", "server/discover", nil, nil)
	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", got.StatusCode, got.Raw)
	}
}

func TestMCPDiscoverAndTools(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	disc := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, nil)
	if disc.StatusCode != http.StatusOK {
		t.Fatalf("discover=%d %s", disc.StatusCode, disc.Raw)
	}
	if disc.Result["resultType"] != resultTypeComplete {
		t.Fatalf("discover=%v", disc.Result)
	}
	vers, _ := disc.Result["supportedVersions"].([]any)
	foundVer := false
	for _, v := range vers {
		if v == protocolVersion {
			foundVer = true
			break
		}
	}
	if !foundVer {
		t.Fatalf("discover missing %s in supportedVersions: %v", protocolVersion, disc.Result)
	}
	if len(vers) != 1 {
		t.Fatalf("discover must advertise only %s, got %v", protocolVersion, vers)
	}
	caps, _ := disc.Result["capabilities"].(map[string]any)
	if caps["tools"] == nil {
		t.Fatalf("discover capabilities=%v", caps)
	}

	listed := mcpRPC(t, h.HTTP, h.Token, "tools/list", nil, nil)
	requireCacheablePrivate(t, listed.Result)
	if listed.Result["resultType"] != resultTypeComplete {
		t.Fatalf("tools/list meta=%v", listed.Result)
	}
	tools, _ := listed.Result["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("expected tools")
	}
	var names []string
	for _, raw := range tools {
		m, _ := raw.(map[string]any)
		name, _ := m["name"].(string)
		names = append(names, name)
		if m["inputSchema"] == nil || m["outputSchema"] == nil {
			t.Fatalf("missing schema for %s", name)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("tools not sorted: %v", names)
	}
	want := []string{"taclab.system.status.get", "taclab.policy.evaluate", "taclab.users.list", "taclab.events.list"}
	for _, n := range want {
		found := false
		for _, got := range names {
			if got == n {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing tool %s in %v", n, names)
		}
	}
	for _, n := range names {
		if strings.HasPrefix(n, "taclab.session.") {
			t.Fatalf("REST_ONLY session tool leaked: %s", n)
		}
	}

	st := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	}, nil)
	sc, _ := st.Result["structuredContent"].(map[string]any)
	if sc["users"] == nil || st.Result["resultType"] != resultTypeComplete {
		t.Fatalf("status=%v", st.Result)
	}

	ev := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name": "taclab.policy.evaluate",
		"arguments": map[string]any{
			"user_id":   "alice",
			"client_id": "sw",
			"service":   "shell",
			"cmd":       "show",
		},
	}, nil)
	tr, _ := ev.Result["structuredContent"].(map[string]any)
	if tr["evaluator"] != "command" || tr["decision"] != "permit_add" {
		t.Fatalf("trace=%v", ev.Result)
	}

	listedEvents := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.events.list",
		"arguments": map[string]any{"limit": 10},
	}, nil)
	if listedEvents.Err != nil {
		t.Fatalf("events.list err=%+v", listedEvents.Err)
	}
	scEv, _ := listedEvents.Result["structuredContent"].(map[string]any)
	if _, ok := scEv["items"]; !ok {
		t.Fatalf("events.list=%v", listedEvents.Result)
	}

	if h.Ring.Accept(events.Event{Category: events.CategoryAuthen, Type: "ascii_login"}).ID == 0 {
		t.Fatal("accept")
	}
	if h.Ring.Accept(events.Event{
		Category: events.CategoryAuthen, Type: "radius.access", Protocol: "radius",
		ListenerRole: "access", PacketCode: "access-request", Outcome: "access_reject",
	}).ID == 0 {
		t.Fatal("accept radius")
	}
	filtered := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name": "taclab.events.list",
		"arguments": map[string]any{
			"protocol":      "radius",
			"listener_role": "access",
		},
	}, nil)
	if filtered.Err != nil {
		t.Fatalf("filtered events.list err=%+v", filtered.Err)
	}
	scF, _ := filtered.Result["structuredContent"].(map[string]any)
	items, _ := scF["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("filtered items=%v", scF)
	}
	item, _ := items[0].(map[string]any)
	if item["type"] != "radius.access" || item["protocol"] != "radius" {
		t.Fatalf("filtered item=%v", item)
	}

	bld := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.build.get",
		"arguments": map[string]any{},
	}, nil)
	scB, _ := bld.Result["structuredContent"].(map[string]any)
	protos, _ := scB["protocols"].(map[string]any)
	rad, _ := protos["radius"].(map[string]any)
	if rad["conformance_status"] != operations.ConformanceStatusPartial {
		t.Fatalf("radius build=%v", scB)
	}
}

func TestScopeFilteredTools(t *testing.T) {
	t.Parallel()
	h := mcpHarnessScopes(t, []string{"state:read"}, config.MCP{})
	listed := mcpRPC(t, h.HTTP, h.Token, "tools/list", nil, nil)
	tools, _ := listed.Result["tools"].([]any)
	for _, raw := range tools {
		m, _ := raw.(map[string]any)
		name, _ := m["name"].(string)
		if name == "taclab.users.create" || name == "taclab.policy.evaluate" || name == "taclab.events.list" {
			t.Fatalf("scope leak: %s", name)
		}
	}
}

func TestEvaluateRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name": "taclab.policy.evaluate",
		"arguments": map[string]any{
			"user_id": "alice",
			"extra":   true,
		},
	}, nil)
	if got.Err == nil || got.Err.Code != codeInvalidParams {
		t.Fatalf("unknown field err=%+v", got.Err)
	}
}

func TestUnknownRPCMethod(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "no/such", nil, nil)
	if got.StatusCode != http.StatusNotFound || got.Err == nil || got.Err.Code != codeMethodNotFound {
		t.Fatalf("got status=%d err=%+v", got.StatusCode, got.Err)
	}
}

func TestPromptsGetStillEnforcesName(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	missing := mcpRPC(t, h.HTTP, h.Token, "prompts/get", map[string]any{"name": "x"}, map[string]string{headerName: ""})
	if missing.StatusCode != http.StatusBadRequest || missing.Err == nil || missing.Err.Code != codeHeaderMismatch {
		t.Fatalf("missing name status=%d err=%+v", missing.StatusCode, missing.Err)
	}
	got := mcpRPC(t, h.HTTP, h.Token, "prompts/get", map[string]any{"name": "x"}, nil)
	if got.Err == nil || got.Err.Code != codeInvalidParams {
		t.Fatalf("prompts/get status=%d err=%+v", got.StatusCode, got.Err)
	}
}

func TestForbiddenOrigin(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	req, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
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

func TestRequireOrigin(t *testing.T) {
	t.Parallel()
	h := mcpHarnessScopes(t, []string{"state:read"}, config.MCP{RequireOrigin: true})
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, nil)
	if got.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", got.StatusCode)
	}
}

func TestSameHostOriginAllowed(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{"Origin": "http://" + strings.TrimPrefix(h.HTTP.URL, "http://")})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", got.StatusCode, got.Raw)
	}
}

func TestProtocolVersionRequired(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{headerProtocolVersion: ""})
	if got.StatusCode != http.StatusBadRequest || got.Err == nil || got.Err.Code != codeHeaderMismatch {
		t.Fatalf("status=%d err=%+v", got.StatusCode, got.Err)
	}
}

func TestUnsupportedProtocolVersion(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{headerProtocolVersion: "2025-11-25"})
	if got.StatusCode != http.StatusBadRequest || got.Err == nil || got.Err.Code != codeUnsupportedVersion {
		t.Fatalf("status=%d err=%+v", got.StatusCode, got.Err)
	}
	data, _ := got.Err.Data.(map[string]any)
	if data == nil {
		t.Fatalf("data=%v", got.Err.Data)
	}
}

// TestAllowLegacyClientsNegotiatesViaSDK covers api.mcp.allow_legacy_clients:
// an older-generation client (an MCP gateway that neither sends the
// MCP-Protocol-Version header nor taclab's _meta envelope) must reach the SDK
// transport, which negotiates the protocol version during initialize. The
// strict default is covered by TestProtocolVersionRequired /
// TestUnsupportedProtocolVersion.
func TestAllowLegacyClientsNegotiatesViaSDK(t *testing.T) {
	t.Parallel()
	h := mcpHarnessScopes(t, []string{
		"state:read", "state:write", "policy:test", "events:read", "tokens:manage",
		"events:sensitive", "config:reload", "config:export", "runtime:reset",
	}, config.MCP{AllowLegacyClients: true})

	legacyInitialize := func(hdr map[string]string) *http.Response {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy-gateway","version":"0.0.1"}}}`
		req, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// No MCP-Protocol-Version header at all (what legacy gateways send).
	resp := legacyInitialize(nil)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	payload := raw
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		payload = nil
		for _, line := range strings.Split(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, "data: "); ok {
				payload = []byte(rest)
				break
			}
		}
	}
	var parsed struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("body=%s err=%v", raw, err)
	}
	if parsed.Error != nil || parsed.Result.ProtocolVersion == "" {
		t.Fatalf("initialize result=%+v err=%+v", parsed.Result, parsed.Error)
	}

	// An older (mismatched) header must also pass through instead of 400.
	resp2 := legacyInitialize(map[string]string{headerProtocolVersion: "2025-03-26"})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("mismatched header status=%d body=%s", resp2.StatusCode, b)
	}
}

func TestHeaderMetaVersionMismatch(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", map[string]any{
		"_meta": map[string]any{
			metaProtocolVersion:    "2025-11-25",
			metaClientCapabilities: map[string]any{},
		},
	}, nil)
	if got.StatusCode != http.StatusBadRequest || got.Err == nil || got.Err.Code != codeHeaderMismatch {
		t.Fatalf("status=%d err=%+v", got.StatusCode, got.Err)
	}
}

func TestMcpMethodRequiredAndMismatch(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	missing := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{headerMethod: ""})
	if missing.StatusCode != http.StatusBadRequest || missing.Err == nil || missing.Err.Code != codeHeaderMismatch {
		t.Fatalf("missing method status=%d err=%+v", missing.StatusCode, missing.Err)
	}
	mismatch := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{headerMethod: "tools/list"})
	if mismatch.StatusCode != http.StatusBadRequest || mismatch.Err == nil || mismatch.Err.Code != codeHeaderMismatch {
		t.Fatalf("mismatch status=%d err=%+v", mismatch.StatusCode, mismatch.Err)
	}
}

func TestMcpNameRequiredAndMismatch(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	missing := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	}, map[string]string{headerName: ""})
	if missing.StatusCode != http.StatusBadRequest || missing.Err == nil || missing.Err.Code != codeHeaderMismatch {
		t.Fatalf("missing name status=%d err=%+v", missing.StatusCode, missing.Err)
	}
	mismatch := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	}, map[string]string{headerName: "other"})
	if mismatch.StatusCode != http.StatusBadRequest || mismatch.Err == nil || mismatch.Err.Code != codeHeaderMismatch {
		t.Fatalf("mismatch status=%d err=%+v", mismatch.StatusCode, mismatch.Err)
	}
}

func TestMcpNameASCII(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	}, map[string]string{headerName: "taclab.system.status.get"})
	if got.StatusCode != http.StatusOK || got.Err != nil {
		t.Fatalf("status=%d err=%+v body=%s", got.StatusCode, got.Err, got.Raw)
	}
}

func TestMcpNameBase64NotDecoded(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	enc := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("taclab.system.status.get")) + "?="
	got := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.system.status.get",
		"arguments": map[string]any{},
	}, map[string]string{headerName: enc})
	if got.StatusCode != http.StatusBadRequest || got.Err == nil || got.Err.Code != codeHeaderMismatch {
		t.Fatalf("base64 Mcp-Name status=%d err=%+v body=%s", got.StatusCode, got.Err, got.Raw)
	}
}

func TestResourcesListAndRead(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	listed := mcpRPC(t, h.HTTP, h.Token, "resources/list", nil, nil)
	requireCacheablePrivate(t, listed.Result)
	if listed.Result["resultType"] != resultTypeComplete {
		t.Fatalf("list=%v", listed.Result)
	}
	resources, _ := listed.Result["resources"].([]any)
	var uris []string
	for _, raw := range resources {
		m, _ := raw.(map[string]any)
		uris = append(uris, m["uri"].(string))
	}
	if !sort.StringsAreSorted(uris) {
		t.Fatalf("uris=%v", uris)
	}
	want := []string{"taclab://status", "taclab://build", "taclab://config/effective", "taclab://users", "taclab://groups", "taclab://clients", "taclab://events/recent"}
	for _, u := range want {
		found := false
		for _, got := range uris {
			if got == u {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing resource %s in %v", u, uris)
		}
	}
	read := mcpRPC(t, h.HTTP, h.Token, "resources/read", map[string]any{"uri": "taclab://status"}, nil)
	if read.Err != nil || read.Result["resultType"] != resultTypeComplete {
		t.Fatalf("read=%v err=%+v", read.Result, read.Err)
	}
	requireCacheablePrivate(t, read.Result)
	contents, _ := read.Result["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("contents=%v", read.Result["contents"])
	}
}

func TestUsersCreateAndListParity(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	created := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name": "taclab.users.create",
		"arguments": map[string]any{
			"id":           "bob",
			"enabled":      false,
			"display_name": "Bob",
		},
	}, nil)
	if created.Err != nil {
		t.Fatalf("create=%+v %s", created.Err, created.Raw)
	}
	sc, _ := created.Result["structuredContent"].(map[string]any)
	if sc["id"] != "bob" || sc["display_name"] != "Bob" {
		t.Fatalf("created=%v", sc)
	}
	listed := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.users.list",
		"arguments": map[string]any{},
	}, nil)
	items, _ := listed.Result["structuredContent"].(map[string]any)["items"].([]any)
	if len(items) < 2 {
		t.Fatalf("users=%v", listed.Result)
	}
}

func TestExpectedRevision(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	created := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.users.create",
		"arguments": map[string]any{"id": "carol", "enabled": false},
	}, nil)
	if created.Err != nil {
		t.Fatalf("create=%+v", created.Err)
	}
	stale := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name": "taclab.users.update",
		"arguments": map[string]any{
			"id":                "carol",
			"display_name":      "Carol",
			"expected_revision": 1,
		},
	}, nil)
	if stale.Err == nil {
		t.Fatal("expected revision mismatch")
	}
	data, _ := stale.Err.Data.(map[string]any)
	if data["code"] != "revision_mismatch" && stale.Err.Message == "" {
		t.Fatalf("err=%+v", stale.Err)
	}
}

func TestAllImplementedToolsBound(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	listed := mcpRPC(t, h.HTTP, h.Token, "tools/list", nil, nil)
	have := map[string]struct{}{}
	for _, raw := range listed.Result["tools"].([]any) {
		m := raw.(map[string]any)
		have[m["name"].(string)] = struct{}{}
	}
	for _, op := range h.Opts.Registry.List() {
		if op.MCP.Kind != "tool" || !op.Implemented {
			continue
		}
		if !auth.Satisfies([]string{
			"state:read", "state:write", "policy:test", "events:read", "tokens:manage",
			"events:sensitive", "config:reload", "config:export", "runtime:reset",
		}, op.Scopes) {
			continue
		}
		if _, ok := have[op.MCP.Name]; !ok {
			t.Errorf("missing bound tool %s", op.MCP.Name)
		}
	}
}

func TestSessionIdIgnored(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	got := mcpRPC(t, h.HTTP, h.Token, "server/discover", nil, map[string]string{"Mcp-Session-Id": "should-ignore"})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", got.StatusCode)
	}
	if strings.Contains(string(got.Raw), "should-ignore") {
		t.Fatal("session id echoed")
	}
}

func requireCacheablePrivate(t *testing.T, result map[string]any) {
	t.Helper()
	if result["ttlMs"] != float64(0) || result["cacheScope"] != cacheScopePrivate {
		t.Fatalf("want ttlMs=0 cacheScope=%q, got %v", cacheScopePrivate, result)
	}
}

type bearerRoundTripper struct {
	token string
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(clone)
}

func TestOfficialSDKClient(t *testing.T) {
	t.Parallel()
	h := mcpHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "taclab-sdk-test", Version: "test"}, nil)
	sess, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{
		Endpoint:             h.HTTP.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerRoundTripper{token: h.Token}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("sdk connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("expected tools from official SDK client")
	}
	if tools.CacheScope != cacheScopePrivate || tools.TTLMs != 0 {
		t.Fatalf("list cacheable ttlMs=%d cacheScope=%q", tools.TTLMs, tools.CacheScope)
	}
	got, err := sess.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "taclab.system.status.get",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call status: %v", err)
	}
	if got.StructuredContent == nil {
		t.Fatalf("status structuredContent=%+v", got)
	}
}

func TestMissingScopeIsPermissionDenied(t *testing.T) {
	t.Parallel()
	h := mcpHarnessScopes(t, []string{"state:read"}, config.MCP{})
	got := mcpRPC(t, h.HTTP, h.Token, "tools/call", map[string]any{
		"name":      "taclab.users.create",
		"arguments": map[string]any{"id": "blocked", "enabled": false},
	}, nil)
	if got.Err == nil {
		t.Fatal("expected permission denied")
	}
	if got.Err.Code == codeMethodNotFound {
		t.Fatalf("missing scope leaked as unknown method: %+v", got.Err)
	}
	data, _ := got.Err.Data.(map[string]any)
	if data["code"] != "permission_denied" && !strings.Contains(got.Err.Message, "scope") && !strings.Contains(got.Err.Message, "permission") {
		t.Fatalf("err=%+v", got.Err)
	}
}

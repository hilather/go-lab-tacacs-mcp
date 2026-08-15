package parity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/mcp"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	parityYAML = `
schema_version: 1
server:
  instance_id: lab-legacy
api:
  rate_limits: {enabled: false}
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16", "2001:db8:20::/48"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
    authorization:
      default_group_ids: [ops]
groups:
  - id: ops
    display_name: Operators
    priority: 10
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
      challenge:
        secret: {file: /run/secrets/alice-chal}
      enable:
        verifier: {file: /run/secrets/alice-enable}
`
	mcpProtocolVersion = "2026-07-28"
	tokenID            = "lab"
)

var (
	parityClock   = fixedClock{t: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)}
	parityHMACKey = bytes.Repeat([]byte{0x11}, 32)
	allScopes     = []string{
		"state:read", "state:write", "policy:test", "events:read", "tokens:manage",
		"events:sensitive", "config:reload", "config:export", "runtime:reset",
	}
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type world struct {
	Name     string
	Mgr      *state.Manager
	Ring     *events.Ring
	Registry *operations.Registry
	Auth     *auth.Service
	HTTP     *httptest.Server
	Token    string
	Actor    operations.Actor
}

func newWorld(t testing.TB, name string, scopes []string, adapters string) *world {
	t.Helper()
	if scopes == nil {
		scopes = allScopes
	}
	doc, err := config.Parse([]byte(parityYAML))
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := state.New(doc, state.Options{Clock: parityClock, HMACKey: parityHMACKey})
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.New(auth.Options{Clock: parityClock})
	ring := events.New(64, parityClock)
	t.Cleanup(ring.Close)
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{Clock: parityClock})
	if err != nil {
		t.Fatal(err)
	}
	aaaSvc, err := aaa.New(aaa.Options{Manager: mgr, Events: ring, Clock: parityClock, Creds: credentials.Options{Clock: parityClock}})
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
		AAA:      aaaSvc,
		LoadBaseline: func() (*config.Document, error) {
			return config.Parse([]byte(parityYAML))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := credentials.IssueBearer(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	rev := mgr.Revision()
	if _, err := mgr.CreateToken(state.CreateToken{
		ID:       tokenID,
		Name:     tokenID,
		Scopes:   append([]string(nil), scopes...),
		Material: credentials.NewTokenMaterial([]byte(value)),
	}, &rev); err != nil {
		t.Fatal(err)
	}
	w := &world{
		Name:     name,
		Mgr:      mgr,
		Ring:     ring,
		Registry: reg,
		Auth:     svc,
		Token:    value,
		Actor:    operations.Actor{ID: tokenID, Scopes: append([]string(nil), scopes...)},
	}
	switch adapters {
	case "rest":
		s := &rest.Server{
			Registry:     reg,
			Snapshot:     mgr.Snapshot,
			Auth:         svc,
			Events:       ring,
			Ready:        func() bool { return true },
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		w.HTTP = httptest.NewServer(s.Handler())
		t.Cleanup(w.HTTP.Close)
	case "mcp":
		w.HTTP = httptest.NewServer(mcp.Handler(mcp.Options{
			Registry:     reg,
			Snapshot:     mgr.Snapshot,
			Auth:         svc,
			Events:       ring,
			Version:      "test",
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}))
		t.Cleanup(w.HTTP.Close)
	case "both":
		s := &rest.Server{
			Registry:     reg,
			Snapshot:     mgr.Snapshot,
			Auth:         svc,
			Events:       ring,
			Ready:        func() bool { return true },
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		mux := http.NewServeMux()
		mux.Handle("/mcp", mcp.Handler(mcp.Options{
			Registry:     reg,
			Snapshot:     mgr.Snapshot,
			Auth:         svc,
			Events:       ring,
			Version:      "test",
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}))
		mux.Handle("/", s.Handler())
		w.HTTP = httptest.NewServer(mux)
		t.Cleanup(w.HTTP.Close)
	}
	return w
}

func isolatedTrio(t testing.TB, scopes []string) (direct, restW, mcpW *world) {
	t.Helper()
	return newWorld(t, "direct", scopes, ""),
		newWorld(t, "rest", scopes, "rest"),
		newWorld(t, "mcp", scopes, "mcp")
}

type callOpts struct {
	Token            string
	OmitAuth         bool
	ExpectedRevision *domain.Revision
	IdempotencyKey   string
	// Body, when set, is the REST/MCP payload without wireRequest stripping.
	Body map[string]any
}

type callOut struct {
	Code     string
	Revision domain.Revision
	Data     any
	Raw      []byte
	HTTP     int
}

func invoke(t testing.TB, w *world, id string, req any, opts callOpts) callOut {
	t.Helper()
	op, ok := w.Registry.Lookup(id)
	if !ok {
		t.Fatalf("unknown operation %s", id)
	}
	switch w.Name {
	case "direct":
		return invokeDirect(t, w, id, req, opts)
	case "rest":
		return invokeREST(t, w, op, req, opts)
	case "mcp":
		return invokeMCP(t, w, op, req, opts)
	default:
		t.Fatalf("unknown world %q", w.Name)
		return callOut{}
	}
}

func invokeDirect(t testing.TB, w *world, id string, req any, opts callOpts) callOut {
	t.Helper()
	res, err := w.Registry.Invoke(context.Background(), id, w.Mgr.Snapshot(), operations.Input{
		Actor:            w.Actor,
		ExpectedRevision: opts.ExpectedRevision,
		IdempotencyKey:   opts.IdempotencyKey,
		Request:          req,
	})
	if err != nil {
		de, ok := domain.AsError(err)
		if !ok {
			t.Fatalf("direct %s: %v", id, err)
		}
		return callOut{Code: string(de.Code), Revision: w.Mgr.Revision()}
	}
	return callOut{Revision: res.Revision, Data: asJSONValue(res.Data)}
}

func invokeREST(t testing.TB, w *world, op operations.Operation, req any, opts callOpts) callOut {
	t.Helper()
	if op.REST.Method == "" || op.REST.Path == "" {
		t.Fatalf("%s missing REST binding", op.ID)
	}
	fields := wireRequest(req)
	if opts.Body != nil {
		fields = opts.Body
	}
	path := op.REST.Path
	if id, ok := fields["id"].(string); ok && strings.Contains(path, "{id}") {
		path = strings.ReplaceAll(path, "{id}", url.PathEscape(id))
	}
	u := w.HTTP.URL + path
	var body []byte
	switch op.REST.Method {
	case http.MethodGet, http.MethodDelete:
		q := url.Values{}
		for k, v := range fields {
			if k == "id" {
				continue
			}
			restQuery(q, k, v)
		}
		if enc := q.Encode(); enc != "" {
			u += "?" + enc
		}
	default:
		var err error
		body, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) == "{}" || string(body) == "null" {
			body = nil
		}
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequest(op.REST.Method, u, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.OmitAuth {
		token := w.Token
		if opts.Token != "" {
			token = opts.Token
		}
		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if opts.ExpectedRevision != nil {
		httpReq.Header.Set("If-Match", fmt.Sprintf(`"revision-%d"`, *opts.ExpectedRevision))
	}
	if opts.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", opts.IdempotencyKey)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := callOut{HTTP: resp.StatusCode, Raw: raw, Revision: w.Mgr.Revision()}
	if resp.StatusCode >= 400 {
		out.Code = restErrorCode(raw, resp.StatusCode)
		return out
	}
	var env struct {
		Revision uint64 `json:"revision"`
		Data     any    `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("rest %s body=%s err=%v", op.ID, raw, err)
	}
	out.Revision = domain.Revision(env.Revision)
	out.Data = env.Data
	return out
}

func invokeMCP(t testing.TB, w *world, op operations.Operation, req any, opts callOpts) callOut {
	t.Helper()
	if op.MCP.Kind != "tool" || op.MCP.Name == "" {
		t.Fatalf("%s missing MCP tool binding", op.ID)
	}
	args := wireRequest(req)
	if opts.Body != nil {
		args = opts.Body
	}
	if args == nil {
		args = map[string]any{}
	}
	if opts.ExpectedRevision != nil {
		args["expected_revision"] = uint64(*opts.ExpectedRevision)
	}
	if opts.IdempotencyKey != "" {
		args["idempotency_key"] = opts.IdempotencyKey
	}
	token := w.Token
	if opts.OmitAuth {
		token = ""
	} else if opts.Token != "" {
		token = opts.Token
	}
	got := mcpRPC(t, w.HTTP, token, "tools/call", map[string]any{
		"name":      op.MCP.Name,
		"arguments": args,
	})
	out := callOut{HTTP: got.status, Raw: got.raw, Revision: w.Mgr.Revision()}
	if got.status == http.StatusUnauthorized {
		out.Code = string(domain.CodeUnauthenticated)
		return out
	}
	if got.status == http.StatusForbidden {
		out.Code = string(domain.CodePermissionDenied)
		return out
	}
	if got.err != nil {
		out.Code = mcpErrorCode(got.err)
		return out
	}
	out.Data = got.result["structuredContent"]
	if rev, ok := revisionOf(out.Data); ok {
		out.Revision = rev
	}
	return out
}

func restQuery(q url.Values, key string, v any) {
	switch key {
	case "categories":
		switch got := v.(type) {
		case []any:
			for _, item := range got {
				q.Add("category", fmt.Sprint(item))
			}
		case []string:
			for _, item := range got {
				q.Add("category", item)
			}
		}
		return
	}
	switch got := v.(type) {
	case nil:
	case bool:
		q.Set(key, strconv.FormatBool(got))
	case float64:
		q.Set(key, strconv.FormatInt(int64(got), 10))
	case json.Number:
		q.Set(key, got.String())
	default:
		s := fmt.Sprint(v)
		if s != "" && s != "0" && s != "false" && s != "<nil>" {
			q.Set(key, s)
		}
	}
}

func restErrorCode(raw []byte, status int) string {
	var problem struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(raw, &problem) == nil && problem.Code != "" {
		return problem.Code
	}
	switch status {
	case http.StatusUnauthorized:
		return string(domain.CodeUnauthenticated)
	case http.StatusForbidden:
		return string(domain.CodePermissionDenied)
	default:
		return string(domain.CodeInternal)
	}
}

func mcpErrorCode(err *rpcErr) string {
	if err == nil {
		return ""
	}
	if m, ok := err.Data.(map[string]any); ok {
		if c, ok := m["code"].(string); ok && c != "" {
			return c
		}
	}
	return err.Message
}

func revisionOf(v any) (domain.Revision, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return 0, false
	}
	for _, key := range []string{"revision", "effective_revision"} {
		switch n := m[key].(type) {
		case float64:
			return domain.Revision(n), true
		case json.Number:
			u, err := n.Int64()
			if err == nil {
				return domain.Revision(u), true
			}
		}
	}
	return 0, false
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

type rpcGot struct {
	status int
	result map[string]any
	err    *rpcErr
	raw    []byte
}

func mcpRPC(t testing.TB, ts *httptest.Server, token, method string, params map[string]any) rpcGot {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	if _, ok := params["_meta"]; !ok {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    mcpProtocolVersion,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "taclab-parity", "version": "test"},
		}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Set("Mcp-Method", method)
	if name, _ := params["name"].(string); name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	if uri, _ := params["uri"].(string); uri != "" {
		req.Header.Set("Mcp-Name", uri)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Result map[string]any `json:"result"`
		Error  *rpcErr        `json:"error"`
	}
	if len(bytes.TrimSpace(raw)) > 0 && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("mcp body=%s err=%v", raw, err)
		}
	}
	return rpcGot{status: resp.StatusCode, result: parsed.Result, err: parsed.Error, raw: raw}
}

func wireRequest(v any) map[string]any {
	m := asMap(v)
	for _, k := range []string{"login", "challenge", "enable", "shared_secret"} {
		sub, ok := m[k].(map[string]any)
		if !ok {
			continue
		}
		file, _ := sub["file"].(string)
		env, _ := sub["environment"].(string)
		if file == "" && env == "" {
			delete(m, k)
		}
	}
	return m
}

func asMap(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func asJSONValue(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

func canonicalJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

type eventKey struct {
	Type     string
	Category string
	Result   string
	Revision domain.Revision
}

func domainEvents(w *world) []eventKey {
	if w.Ring == nil {
		return nil
	}
	page := w.Ring.Read(events.Query{Limit: events.MaxLimit})
	out := make([]eventKey, 0, len(page.Items))
	for _, ev := range page.Items {
		out = append(out, eventKey{Type: ev.Type, Category: ev.Category, Result: ev.Result, Revision: ev.Revision})
	}
	return out
}

func compareWorlds(t *testing.T, id string, a, b *world, ao, bo callOut, normalize func(any) any) {
	t.Helper()
	if ao.Code != bo.Code {
		t.Errorf("%s %s vs %s code %q != %q", id, a.Name, b.Name, ao.Code, bo.Code)
	}
	if ao.Code != "" {
		return
	}
	da, db := stripVolatile(ao.Data), stripVolatile(bo.Data)
	if normalize != nil {
		da, db = normalize(da), normalize(db)
	}
	if canonicalJSON(da) != canonicalJSON(db) {
		t.Errorf("%s %s vs %s data\n%s\n%s", id, a.Name, b.Name, canonicalJSON(da), canonicalJSON(db))
	}
	if a.Mgr.Revision() != b.Mgr.Revision() {
		t.Errorf("%s %s vs %s snapshot revision %d != %d", id, a.Name, b.Name, a.Mgr.Revision(), b.Mgr.Revision())
	}
	if !reflect.DeepEqual(domainEvents(a), domainEvents(b)) {
		t.Errorf("%s %s vs %s events %v != %v", id, a.Name, b.Name, domainEvents(a), domainEvents(b))
	}
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }

func goJSONFields(typ reflect.Type) []string {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		return nil
	}
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			names = append(names, goJSONFields(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func goWriteOnlyFields(typ reflect.Type) []string {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		return nil
	}
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			names = append(names, goWriteOnlyFields(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		if name == "password" || name == "data" || ft.Name() == "OptionalSecret" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func stripVolatile(v any) any {
	switch got := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(got))
		for k, val := range got {
			if k == "last_used_at" || k == "request_id" {
				continue
			}
			out[k] = stripVolatile(val)
		}
		return out
	case []any:
		out := make([]any, len(got))
		for i, val := range got {
			out[i] = stripVolatile(val)
		}
		return out
	default:
		return v
	}
}

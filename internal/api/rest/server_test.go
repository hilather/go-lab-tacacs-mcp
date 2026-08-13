package rest

import (
	"bytes"
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
)

type harness struct {
	Server *Server
	HTTP   *httptest.Server
	Token  string
	Auth   *auth.Service
	Mgr    *state.Manager
	Ring   *events.Ring
}

func restHarness(t testing.TB) *harness {
	t.Helper()
	return restHarnessScopes(t, []string{
		"state:read", "state:write", "policy:test", "events:read", "tokens:manage",
		"events:sensitive", "config:reload", "config:export", "runtime:reset",
	})
}

func restHarnessScopes(t testing.TB, scopes []string) *harness {
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
	s := &Server{
		Registry:     reg,
		Snapshot:     mgr.Snapshot,
		Auth:         svc,
		Events:       ring,
		Ready:        func() bool { return true },
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{Server: s, HTTP: ts, Token: value, Auth: svc, Mgr: mgr, Ring: ring}
}

func doAuth(t testing.TB, method, url, token string, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHealthUnauthenticated(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	for _, path := range []string{"/health/live", "/health/ready"} {
		resp, err := http.Get(h.HTTP.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", path, resp.StatusCode)
		}
		if resp.Header.Get("X-Request-ID") == "" {
			t.Fatal("request id")
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("security header")
		}
		_ = resp.Body.Close()
	}
}

func TestReadyFailsWhenNotReady(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	h.Server.Ready = func() bool { return false }
	ts := httptest.NewServer(h.Server.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestStatusRequiresBearer(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp, err := http.Get(h.HTTP.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("www-authenticate=%q", resp.Header.Get("WWW-Authenticate"))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("ct=%s", ct)
	}
}

func TestStatusAndEvaluate(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/status", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b)
	}
	if !strings.Contains(resp.Header.Get("ETag"), "revision-") {
		t.Fatalf("etag=%q", resp.Header.Get("ETag"))
	}
	var env struct {
		Revision  uint64            `json:"revision"`
		RequestID string            `json:"request_id"`
		Data      operations.Status `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Revision == 0 || env.Data.Users != 1 || env.RequestID == "" {
		t.Fatalf("env=%+v", env)
	}

	body, _ := json.Marshal(operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show"})
	presp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/policy/evaluate", h.Token, body, nil)
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(presp.Body)
		t.Fatalf("evaluate=%d %s", presp.StatusCode, b)
	}
	var penv struct {
		Data operations.PolicyTrace `json:"data"`
	}
	if err := json.NewDecoder(presp.Body).Decode(&penv); err != nil {
		t.Fatal(err)
	}
	if penv.Data.Evaluator != "command" || penv.Data.Decision != "permit_add" {
		t.Fatalf("trace=%+v", penv.Data)
	}
}

func TestBuild(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/build", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
	var env struct {
		Data operations.BuildInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Version != "test" || env.Data.MCPSpecification == "" {
		t.Fatalf("build=%+v", env.Data)
	}
}

func TestListEvents(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	if h.Ring.Accept(events.Event{Category: events.CategoryAcct, Type: "start"}).ID == 0 {
		t.Fatal("accept")
	}
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/events?limit=10&category=acct", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
	var env struct {
		Data operations.EventList `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data.Items) != 1 {
		t.Fatalf("items=%+v", env.Data.Items)
	}
}

func TestEvaluateRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	presp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/policy/evaluate", h.Token, []byte(`{"user_id":"alice","extra":true}`), nil)
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", presp.StatusCode)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(presp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "invalid_argument" {
		t.Fatalf("code=%q", problem.Code)
	}
}

func TestMCPOnlyRoutesStayUnbound(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/mcp/discover", h.Token, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("mcp-only path should be unbound, status=%d", resp.StatusCode)
	}
}

func TestOversizedBody(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	h.Server.MaxBody = 32
	ts := httptest.NewServer(h.Server.Handler())
	t.Cleanup(ts.Close)
	body := bytes.Repeat([]byte("a"), 64)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/policy/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPanicRecovery(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	s := &Server{}
	h := s.withRecover(inner)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestRequestIDEcho(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/status", h.Token, nil, map[string]string{headerRequestID: "req-fixed-1"})
	defer resp.Body.Close()
	if resp.Header.Get(headerRequestID) != "req-fixed-1" {
		t.Fatalf("id=%q", resp.Header.Get(headerRequestID))
	}
}

func TestIfMatchAndIdempotencyParsed(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	body, _ := json.Marshal(operations.CreateTokenRequest{ID: "ci", Name: "CI", Scopes: []string{"state:read"}})
	resp := doAuth(t, http.MethodPost, h.HTTP.URL+"/api/v1/tokens", h.Token, body, map[string]string{
		headerIfMatch:     `"revision-999"`,
		headerIdempotency: "idem-1",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d %s", resp.StatusCode, b)
	}
}

func TestInFlightLimit(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	limited := &Server{
		Registry:    h.Server.Registry,
		Snapshot:    h.Server.Snapshot,
		Auth:        h.Server.Auth,
		Events:      h.Server.Events,
		Ready:       h.Server.Ready,
		MaxInFlight: 1,
	}
	limited.init()
	block := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hold", func(w http.ResponseWriter, r *http.Request) {
		close(block)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(limited.wrap(mux))
	t.Cleanup(ts.Close)
	go func() {
		resp, err := http.Get(ts.URL + "/hold")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-block:
	case <-time.After(2 * time.Second):
		t.Fatal("hold")
	}
	resp, err := http.Get(ts.URL + "/hold")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	close(release)
}

func TestNoCORS(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	resp := doAuth(t, http.MethodGet, h.HTTP.URL+"/api/v1/status", h.Token, nil, map[string]string{"Origin": "https://evil.example"})
	defer resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS must be disabled")
	}
}

func TestFrozenRESTMatchesImplemented(t *testing.T) {
	t.Parallel()
	h := restHarness(t)
	got := append([]string(nil), h.Server.Registry.ImplementedIDs()...)
	want := append([]string(nil), FrozenREST...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("implemented=%v frozen=%v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("implemented=%v frozen=%v", got, want)
		}
	}
}

func TestParseIfMatch(t *testing.T) {
	t.Parallel()
	rev, err := parseIfMatch(`"revision-42"`)
	if err != nil || rev == nil || *rev != 42 {
		t.Fatalf("got %v %v", rev, err)
	}
	if _, err := parseIfMatch("nope"); err == nil {
		t.Fatal("expected error")
	}
	if got, err := parseIfMatch(""); err != nil || got != nil {
		t.Fatalf("empty %v %v", got, err)
	}
}

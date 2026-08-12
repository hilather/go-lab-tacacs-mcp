package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const restToken = "lab-bootstrap-token-32-bytes!!!"

func restHarness(t *testing.T) (*Server, *httptest.Server) {
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
	}, func(config.SecretRef) ([]byte, error) { return []byte(restToken), nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Registry: reg, Snapshot: mgr.Snapshot, Auth: v, Ready: func() bool { return true }}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestHealthUnauthenticated(t *testing.T) {
	t.Parallel()
	_, ts := restHarness(t)
	for _, path := range []string{"/health/live", "/health/ready"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", path, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestStatusRequiresBearer(t *testing.T) {
	t.Parallel()
	_, ts := restHarness(t)
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestStatusAndEvaluate(t *testing.T) {
	t.Parallel()
	_, ts := restHarness(t)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+restToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b)
	}
	var env struct {
		Revision uint64            `json:"revision"`
		Data     operations.Status `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Revision == 0 || env.Data.Users != 1 {
		t.Fatalf("env=%+v", env)
	}

	body, _ := json.Marshal(operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show"})
	preq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/policy/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	preq.Header.Set("Authorization", "Bearer "+restToken)
	preq.Header.Set("Content-Type", "application/json")
	presp, err := http.DefaultClient.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
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

func TestEventsStubClearsDeadline(t *testing.T) {
	t.Parallel()
	s, _ := restHarness(t)
	hs := &http.Server{Addr: "127.0.0.1:0", Handler: s.Handler(), WriteTimeout: 50 * time.Millisecond}
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go hs.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { _ = hs.Close() })

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+restToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("ct=%s", ct)
	}
	buf := make([]byte, 32)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], []byte("keepalive")) {
		t.Fatalf("body=%q", buf[:n])
	}
}

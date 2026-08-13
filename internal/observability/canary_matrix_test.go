package observability_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	mcpapi "github.com/hilather/go-lab-tacacs-mcp/internal/api/mcp"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestFullCanaryMatrix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, val string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	legacyPath := write("legacy", observability.CanaryLegacyShared)
	loginPath := write("login", observability.CanaryLogin)
	chalPath := write("challenge", observability.CanaryChallenge)
	enablePath := write("enable", observability.CanaryEnable)
	tlsPath := write("tlskey", observability.CanaryTLSKey)
	tokPath := write("bootstrap", "lab-bootstrap-token-value-32b!!")

	yamlSrc := fmt.Sprintf(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
security:
  legacy_shared_secrets:
    minimum_character_classes: 0
    reject_known_weak_values: false
    minimum_length_characters: 8
clients:
  - id: sw
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: %s}}
users:
  - id: alice
    credentials:
      login: {verifier: {file: %s}}
      challenge: {secret: {file: %s}}
      enable: {verifier: {file: %s}}
api:
  bootstrap_tokens:
    - id: lab
      token: {file: %s}
      scopes: [state:read, state:write, tokens:manage, config:export, events:read, events:sensitive, policy:test]
`, legacyPath, loginPath, chalPath, enablePath, tokPath)

	doc, err := config.Parse([]byte(yamlSrc))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) {
		if ref.File == "" {
			return nil, fmt.Errorf("missing file")
		}
		return os.ReadFile(ref.File)
	}
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.LoadBootstrap(mgr.Snapshot(), lookup); err != nil {
		t.Fatal(err)
	}
	svc := auth.New(auth.Options{})
	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	tr := observability.NewTracer(true)
	ring := events.NewWithOptions(events.Options{Capacity: 32, Metrics: rec, Stdout: &bytes.Buffer{}, RedactUserInput: true})
	t.Cleanup(ring.Close)
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := operations.NewFromRepo(".", operations.Deps{
		Build:    operations.BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-12T00:00:00Z"},
		State:    mgr,
		Sessions: svc,
		Usage:    svc,
		Events:   ring,
		Secrets:  lookup,
		Creds:    creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	value := "lab-bootstrap-token-value-32b!!"
	var logBuf bytes.Buffer
	lg := observability.NewJSONLogger(&logBuf, 0)
	rs := &rest.Server{
		Registry: ops,
		Snapshot: mgr.Snapshot,
		Auth:     svc,
		Events:   ring,
		Ready:    func() bool { return true },
		Logger:   lg,
		Metrics:  rec,
		Tracer:   tr,
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpapi.Handler(mcpapi.Options{
		Registry: ops, Snapshot: mgr.Snapshot, Auth: svc, Events: ring,
		Metrics: rec, Tracer: tr, Version: "test",
	}))
	mux.Handle("/", rs.Handler())
	ts := startHTTPTest(t, mux)
	defer ts.Close()

	// Error paths plant token and cookie canaries as untrusted input.
	bad := do(t, http.MethodGet, ts.URL+"/api/v1/status", "not-a-token-"+observability.CanaryToken, nil)
	cookieHdr := http.Header{}
	cookieHdr.Set("Cookie", "taclab_session="+observability.CanaryCookie)
	cookieEcho := doHeaders(t, http.MethodGet, ts.URL+"/api/v1/status", value, nil, cookieHdr)

	authn := do(t, http.MethodPost, ts.URL+"/api/v1/authentication/test", value, []byte(
		`{"user_id":"alice","method":"ascii","password":"`+observability.CanaryPassword+`"}`))
	created := do(t, http.MethodPost, ts.URL+"/api/v1/tokens", value, []byte(`{"id":"canary","scopes":["state:read"]}`))
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(created, &env)
	listed := do(t, http.MethodGet, ts.URL+"/api/v1/tokens", value, nil)
	users := do(t, http.MethodGet, ts.URL+"/api/v1/users", value, nil)
	clients := do(t, http.MethodGet, ts.URL+"/api/v1/clients", value, nil)
	exported := do(t, http.MethodGet, ts.URL+"/api/v1/config/export", value, nil)
	evs := do(t, http.MethodGet, ts.URL+"/api/v1/events", value, nil)
	status := do(t, http.MethodGet, ts.URL+"/api/v1/status", value, nil)
	openAPI := do(t, http.MethodGet, ts.URL+"/api/openapi.json", "", nil)
	sess := do(t, http.MethodPost, ts.URL+"/api/v1/session", value, nil)

	mcpBad := mcpCall(t, ts.URL, "not-a-token-"+observability.CanaryToken, "server/discover", nil)
	mcpStatus := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.system.status.get", "arguments": map[string]any{},
	})
	mcpExport := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.config.export", "arguments": map[string]any{},
	})
	mcpEvents := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.events.list", "arguments": map[string]any{"limit": 20},
	})
	mcpAuthn := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.authentication.test",
		"arguments": map[string]any{
			"user_id": "alice", "method": "ascii", "password": observability.CanaryPassword,
		},
	})

	opts := config.ReadOptions{StrictFiles: false, StrictFilesSet: true}
	_, _, loginErr := config.ReadSecret(config.SecretRef{Purpose: credentials.PurposeLoginVerifier, File: loginPath}, opts)
	loginErrText := ""
	if loginErr != nil {
		loginErrText = loginErr.Error()
	}
	_, tlsHolder, tlsErr := config.ReadSecret(config.SecretRef{Purpose: credentials.PurposeTLSPrivateKey, File: tlsPath}, opts)
	tlsDump := fmt.Sprintf("%v %#v %v", tlsHolder, tlsHolder, tlsErr)

	var evBuf bytes.Buffer
	for _, e := range ring.Snapshot() {
		_ = events.WriteJSON(&evBuf, e, true)
	}
	traces := tr.SpanDump()
	counts := map[string]int{}
	for st, n := range mgr.Snapshot().LifecycleCounts() {
		counts[string(st)] = n
	}
	rec.SetSecretLifecycle(counts)
	var metrics bytes.Buffer
	if err := reg.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}

	var panicBuf bytes.Buffer
	func() {
		lg := observability.NewJSONLogger(&panicBuf, 0)
		defer func() {
			if rec := recover(); rec != nil {
				lg.Error("recovered", "err", "panic")
			}
		}()
		panic(observability.CanaryPassword)
	}()

	surfaces := []struct {
		name  string
		blob  string
		allow []string
	}{
		{"rest-unauth", string(bad), nil},
		{"rest-cookie-header", string(cookieEcho), nil},
		{"rest-authn-test", string(authn), nil},
		{"rest-tokens-create", string(created), []string{env.Data.Token}},
		{"rest-tokens-list", string(listed), nil},
		{"rest-users", string(users), nil},
		{"rest-clients", string(clients), nil},
		{"rest-export", string(exported), nil},
		{"rest-events", string(evs), nil},
		{"rest-status", string(status), nil},
		{"rest-session", string(sess), nil},
		{"openapi", string(openAPI), nil},
		{"mcp-unauth", string(mcpBad), nil},
		{"mcp-status", string(mcpStatus), nil},
		{"mcp-export", string(mcpExport), nil},
		{"mcp-events", string(mcpEvents), nil},
		{"mcp-authn-test", string(mcpAuthn), nil},
		{"event-ring-json", evBuf.String(), nil},
		{"logs", logBuf.String(), nil},
		{"metrics", metrics.String(), nil},
		{"traces", traces, nil},
		{"login-verifier-error", loginErrText, nil},
		{"tls-key-holder", tlsDump, nil},
		{"panic", panicBuf.String(), nil},
	}
	for _, s := range surfaces {
		if hits := observability.ScanCanaries(s.blob, s.allow...); len(hits) > 0 {
			t.Error(observability.FormatHits(s.name, hits) + "\n" + s.blob)
		}
		if env.Data.Token != "" && s.name != "rest-tokens-create" && strings.Contains(s.blob, env.Data.Token) {
			t.Errorf("%s leaked one-time token", s.name)
		}
		if strings.Contains(s.blob, value) {
			t.Errorf("%s leaked bootstrap token", s.name)
		}
	}
	if env.Data.Token == "" {
		t.Fatal("missing one-time token from create")
	}
}

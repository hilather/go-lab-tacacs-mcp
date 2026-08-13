package observability_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Full canary matrix: plant unique values per secret class and scan every
// output surface this package can reach without the UI or container lab.
func TestFullCanaryMatrix(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	yamlSrc := `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: /run/secrets/sw}}
users:
  - id: alice
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
	ring := events.NewWithOptions(events.Options{Capacity: 32, Metrics: rec})
	t.Cleanup(ring.Close)
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{})
	if err != nil {
		t.Fatal(err)
	}
	regy, err := operations.NewFromRepo(".", operations.Deps{
		Build:    operations.BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-12T00:00:00Z"},
		State:    mgr,
		Sessions: svc,
		Usage:    svc,
		Events:   ring,
		Creds:    creds,
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
		ID: "lab", Name: "lab",
		Scopes:   []string{"state:read", "state:write", "tokens:manage", "config:export", "events:read", "events:sensitive", "policy:test"},
		Material: credentials.NewTokenMaterial([]byte(value)),
	}, &rev); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	lg := observability.NewJSONLogger(&logBuf, 0)
	rs := &rest.Server{
		Registry: regy,
		Snapshot: mgr.Snapshot,
		Auth:     svc,
		Events:   ring,
		Ready:    func() bool { return true },
		Logger:   lg,
		Metrics:  rec,
	}
	ts := startHTTPTest(t, rs.Handler())
	defer ts.Close()

	bad := do(t, http.MethodGet, ts.URL+"/api/v1/status", "not-a-token-"+observability.CanaryToken, nil)
	created := do(t, http.MethodPost, ts.URL+"/api/v1/tokens", value, []byte(`{"id":"canary","scopes":["state:read"]}`))
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(created, &env)
	listed := do(t, http.MethodGet, ts.URL+"/api/v1/tokens", value, nil)
	exported := do(t, http.MethodGet, ts.URL+"/api/v1/config/export", value, nil)
	evs := do(t, http.MethodGet, ts.URL+"/api/v1/events", value, nil)
	status := do(t, http.MethodGet, ts.URL+"/api/v1/status", value, nil)
	openAPI := do(t, http.MethodGet, ts.URL+"/api/openapi.json", "", nil)

	ring.Accept(events.Event{Category: events.CategoryAuthen, Type: "ascii", Result: "fail", UserID: "alice"})
	var evBuf bytes.Buffer
	for _, e := range ring.Snapshot() {
		_ = events.WriteJSON(&evBuf, e, true)
	}

	rec.Authen("legacy", "ascii", "fail")
	rec.SetSecretLifecycle(map[string]int{observability.StatusCurrent: 1})
	var metrics bytes.Buffer
	if err := reg.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}

	surfaces := []struct {
		name  string
		blob  string
		allow []string
	}{
		{"rest-unauth", string(bad), nil},
		{"rest-tokens-list", string(listed), nil},
		{"rest-export", string(exported), nil},
		{"rest-events", string(evs), nil},
		{"rest-status", string(status), nil},
		{"openapi", string(openAPI), nil},
		{"event-ring-json", evBuf.String(), nil},
		{"logs", logBuf.String(), nil},
		{"metrics", metrics.String(), nil},
	}
	for _, s := range surfaces {
		if hits := observability.ScanCanaries(s.blob, s.allow...); len(hits) > 0 {
			t.Error(observability.FormatHits(s.name, hits) + "\n" + s.blob)
		}
		if env.Data.Token != "" && strings.Contains(s.blob, env.Data.Token) {
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

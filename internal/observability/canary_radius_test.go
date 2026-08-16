package observability_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
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

func TestRADIUSCanaryMatrix(t *testing.T) {
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
	radiusPath := write("radius", observability.CanaryRADIUSShared)
	loginPath := write("login", observability.CanaryLogin)
	chalPath := write("challenge", observability.CanaryMSCHAP)
	tokPath := write("bootstrap", "lab-bootstrap-token-value-32b!!")

	yamlSrc := fmt.Sprintf(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access: {enabled: false, bind: 0.0.0.0:1812}
    accounting: {enabled: false, bind: 0.0.0.0:1813}
security:
  legacy_shared_secrets:
    minimum_character_classes: 0
    reject_known_weak_values: false
    minimum_length_characters: 8
  radius_shared_secrets:
    minimum_character_classes: 0
    reject_known_weak_values: false
    minimum_length_characters: 8
clients:
  - id: sw
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"]}
    endpoints:
      - id: tacacs-legacy
        protocol: tacacs
        transport: tcp
        roles: [authentication, authorization, accounting]
        tacacs:
          shared_secret: {file: %s}
          allowed_methods: [ascii, pap]
          default_service: login
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: %s}
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [pap, chap, mschapv1, mschapv2]
users:
  - id: alice
    credentials:
      login: {verifier: {file: %s}}
      challenge: {secret: {file: %s}}
api:
  bootstrap_tokens:
    - id: lab
      token: {file: %s}
      scopes: [state:read, state:write, tokens:manage, config:export, events:read, events:sensitive, policy:test, radius:dynamic]
`, legacyPath, radiusPath, loginPath, chalPath, tokPath)

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
	aaaSvc, err := aaa.New(aaa.Options{Manager: mgr, Secrets: lookup, Events: ring, Creds: credentials.Options{}})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := operations.NewFromRepo(".", operations.Deps{
		Build:    operations.BuildMeta{Version: "test", Commit: "abc", BuildTime: "2026-08-14T00:00:00Z"},
		State:    mgr,
		Sessions: svc,
		Usage:    svc,
		Events:   ring,
		Secrets:  lookup,
		Creds:    creds,
		AAA:      aaaSvc,
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

	authn := do(t, http.MethodPost, ts.URL+"/api/v1/authentication/test", value, []byte(
		`{"user_id":"alice","method":"pap","password":"`+observability.CanaryUserPassword+`"}`))
	clients := do(t, http.MethodGet, ts.URL+"/api/v1/clients", value, nil)
	exported := do(t, http.MethodGet, ts.URL+"/api/v1/config/export", value, nil)
	evs := do(t, http.MethodGet, ts.URL+"/api/v1/events", value, nil)
	status := do(t, http.MethodGet, ts.URL+"/api/v1/status", value, nil)
	users := do(t, http.MethodGet, ts.URL+"/api/v1/users", value, nil)
	authChal := []byte{0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28}
	peer := []byte{0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c, 0x7e}
	msResp := credentials.MSCHAPv2Response([]byte(observability.CanaryMSCHAP), []byte("alice"), authChal, peer)
	msBody, _ := json.Marshal(map[string]any{
		"user_id": "alice", "client_id": "sw",
		"method": map[string]any{
			"type": "mschapv2", "id": 17,
			"challenge": base64.StdEncoding.EncodeToString(authChal),
			"response":  base64.StdEncoding.EncodeToString(msResp),
		},
	})
	mschap := do(t, http.MethodPost, ts.URL+"/api/v1/radius/access:test", value, msBody)
	sessions := do(t, http.MethodGet, ts.URL+"/api/v1/radius/sessions", value, nil)

	mcpExport := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.config.export", "arguments": map[string]any{},
	})
	mcpAuthn := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.authentication.test",
		"arguments": map[string]any{
			"user_id": "alice", "method": "pap", "password": observability.CanaryUserPassword,
		},
	})
	mcpClients := mcpCall(t, ts.URL, value, "tools/call", map[string]any{
		"name": "taclab.clients.list", "arguments": map[string]any{},
	})

	opts := config.ReadOptions{StrictFiles: false, StrictFilesSet: true}
	_, radiusHolder, radiusErr := config.ReadSecret(config.SecretRef{Purpose: credentials.PurposeRADIUSSharedSecret, File: radiusPath}, opts)
	radiusDump := fmt.Sprintf("%v %#v %v", radiusHolder, radiusHolder, radiusErr)

	reg.Inc(observability.MetricProtocolDiscards, observability.Labels{
		observability.LabelProtocol:   observability.ProtocolRADIUS,
		observability.LabelTransport:  observability.TransportUDP,
		observability.LabelRole:       observability.RoleAccess,
		observability.LabelReasonCode: "discard_unknown_client",
		observability.LabelClientID:   observability.CanaryRADIUSShared,
		"user_password":               observability.CanaryUserPassword,
		"ip":                          "192.0.2.10",
	}, 1)
	rec.ProtocolDiscard(observability.ProtocolRADIUS, observability.TransportUDP, observability.RoleAccess, "discard_unknown_client")

	var evBuf bytes.Buffer
	for _, e := range ring.Snapshot() {
		_ = events.WriteJSON(&evBuf, e, true)
	}
	traces := tr.SpanDump()
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
		panic(observability.CanaryUserPassword + observability.CanaryRADIUSShared + observability.CanaryMSCHAP)
	}()

	surfaces := []struct {
		name string
		blob string
	}{
		{"rest-authn-pap", string(authn)},
		{"rest-radius-mschap", string(mschap)},
		{"rest-clients", string(clients)},
		{"rest-export", string(exported)},
		{"rest-events", string(evs)},
		{"rest-status", string(status)},
		{"rest-users", string(users)},
		{"rest-sessions", string(sessions)},
		{"mcp-export", string(mcpExport)},
		{"mcp-authn-pap", string(mcpAuthn)},
		{"mcp-clients", string(mcpClients)},
		{"event-ring-json", evBuf.String()},
		{"logs", logBuf.String()},
		{"metrics", metrics.String()},
		{"traces", traces},
		{"radius-secret-holder", radiusDump},
		{"panic", panicBuf.String()},
	}
	for _, s := range surfaces {
		if hits := observability.ScanCanaries(s.blob); len(hits) > 0 {
			t.Error(observability.FormatHits(s.name, hits) + "\n" + s.blob)
		}
		if strings.Contains(s.blob, value) {
			t.Errorf("%s leaked bootstrap token", s.name)
		}
	}
	// Export must mention the RADIUS secret *file path*, never the bytes.
	if !strings.Contains(string(exported), "radius") && !strings.Contains(string(clients), "sw") {
		t.Fatal("expected RADIUS client in export or list")
	}
	_ = json.Unmarshal(authn, &struct{}{})
}

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func TestEmitLifecycleWarningsSkipsTLSOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	overdueAt := now.Add(-200 * 24 * time.Hour)
	doc, err := config.Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
security:
  legacy_shared_secrets:
    minimum_character_classes: 0
    reject_known_weak_values: false
    minimum_length_characters: 8
    default_rotation_interval: 90d
clients:
  - id: legacy
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy:
      shared_secret: {file: /run/secrets/legacy}
      shared_secret_lifecycle:
        last_rotated_at: 2025-01-01T00:00:00Z
        rotation_interval: 90d
  - id: tls-only
    priority: 20
    match: {source_cidrs: ["10.1.0.0/16"], transports: [tls]}
`))
	if err != nil {
		t.Fatal(err)
	}
	doc.Clients[0].Legacy.SharedSecretLifecycle.LastRotatedAt = &overdueAt
	good := []byte("Str0ng-Shared-Secret!!")
	lookup := func(config.SecretRef) ([]byte, error) {
		return append([]byte(nil), good...), nil
	}
	mgr, err := state.New(doc, state.Options{Clock: clockFunc(now), Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	counts := mgr.Snapshot().LifecycleCounts()
	if counts["unknown"] != 0 {
		t.Fatalf("TLS-only must not count as unknown: %v", counts)
	}
	if counts["overdue"] != 1 {
		t.Fatalf("overdue=%d", counts["overdue"])
	}

	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	emitLifecycleWarnings(rec, mgr.Snapshot())
	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if strings.Contains(text, `taclab_secret_warnings_total{status="unknown"}`) &&
		!strings.Contains(text, `taclab_secret_warnings_total{status="unknown"} 0`) {
		// series is only emitted when incremented
		if strings.Contains(text, `taclab_secret_warnings_total{status="unknown"} 1`) {
			t.Fatalf("TLS-only must not increment unknown warnings:\n%s", text)
		}
	}
	if !strings.Contains(text, `taclab_secret_warnings_total{status="overdue"} 1`) {
		t.Fatalf("expected one overdue warning:\n%s", text)
	}
}

type clockFunc time.Time

func (c clockFunc) Now() time.Time { return time.Time(c) }

func TestComposedAdminMuxOmitsPprof(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("lab-bootstrap-token-value-32b!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `
schema_version: 1
listeners:
  legacy_tacacs: {enabled: false}
  secure_tacacs: {enabled: false}
  http:
    enabled: true
    bind: 127.0.0.1:0
observability:
  metrics:
    enabled: true
    path: /metrics
    expose_on_admin: true
  profiling:
    enabled: true
api:
  bootstrap_tokens:
    - id: lab
      token: {file: ` + tok + `}
      scopes: [state:read]
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	doc.Listeners.HTTP.Bind = "127.0.0.1:0"
	doc.Observability.Metrics.ExposeOnAdmin = true
	doc.Observability.Profiling.Enabled = true
	lookup := secretLookup(doc)
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	ring := events.New(8, nil)
	t.Cleanup(ring.Close)
	obs := observability.New(observability.Options{
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
		ExposeOnAdmin:  true,
		PprofEnabled:   true,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hs, ln, err := startHTTP(filepath.Join(dir, "lab.yaml"), doc, mgr, lookup, nil, ring, nil, logger, obs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Shutdown(context.Background()) })
	go func() { _ = hs.Serve(ln) }()

	base := "http://" + ln.Addr().String()
	pprof, err := http.Get(base + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer pprof.Body.Close()
	body, _ := io.ReadAll(pprof.Body)
	if pprof.StatusCode == http.StatusOK && (bytes.Contains(body, []byte("Types of profiles available")) || bytes.Contains(body, []byte("full goroutine stack dump")) || bytes.Contains(body, []byte("profile?seconds="))) {
		t.Fatalf("pprof served on admin mux: %s", body)
	}
	met, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer met.Body.Close()
	if met.StatusCode != http.StatusOK {
		t.Fatalf("admin /metrics status=%d", met.StatusCode)
	}
}

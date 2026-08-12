package legacy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

const testSecret = "LabSecret-16chars!"

func writeSecret(t *testing.T, dir, name, value string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func testYAML(secretPath, bind, cidrs string) string {
	return fmt.Sprintf(`
schema_version: 1
server:
  shutdown_grace: 1s
listeners:
  legacy_tacacs:
    enabled: true
    bind: %q
    read_timeout: 2s
    write_timeout: 2s
    idle_timeout: 2s
    handshake_timeout: 2s
    max_connections: 16
    max_sessions_per_connection: 8
    max_packet_body_bytes: 65536
    single_connect:
      enabled: true
      max_lifetime: 1m
      idle_timeout: 2s
  secure_tacacs:
    enabled: false
  http:
    enabled: false
clients:
  - id: loop
    display_name: Loop
    priority: 10
    match:
      source_cidrs: [%s]
      transports: [legacy]
    legacy:
      shared_secret: {file: %q}
`, bind, cidrs, secretPath)
}

func startListener(t *testing.T, yaml string, lookup config.SecretLookup) (*Listener, *state.Manager) {
	t.Helper()
	return startListenerH(t, yaml, lookup, server.Stub{})
}

func startListenerH(t *testing.T, yaml string, lookup config.SecretLookup, h server.Handler) (*Listener, *state.Manager) {
	t.Helper()
	doc, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if lookup == nil {
		lookup = func(ref config.SecretRef) ([]byte, error) {
			return os.ReadFile(ref.File)
		}
	}
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = server.Stub{}
	}
	ln, err := Listen(Options{
		Bind:     doc.Listeners.LegacyTACACS.Bind,
		Settings: doc.Listeners.LegacyTACACS,
		Grace:    time.Second,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Handler:  h,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		shut, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = ln.Shutdown(shut)
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})
	deadline := time.Now().Add(time.Second)
	for !ln.Ready() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !ln.Ready() {
		t.Fatal("listener not ready")
	}
	return ln, mgr
}

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

func TestStartHTTPRejectsUnsupportedTLSBeforeBootstrap(t *testing.T) {
	doc, err := config.Parse([]byte("schema_version: 1\nlisteners:\n  secure_tacacs: {enabled: false}\n  http: {tls: {enabled: true}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = startHTTP("", doc, nil, nil, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("HTTP TLS accepted")
	}
}

func TestServeShutdownDeadlineClosesHTTPAndReturnsFailure(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "lab.yaml")
	if err := os.WriteFile(cfg, []byte(`schema_version: 2
server: {admin_only: true, shutdown_grace: 100ms}
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  http: {enabled: true, bind: "127.0.0.1:0", read_header_timeout: 1m}
observability:
  metrics: {enabled: false}
`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	result := make(chan error, 1)
	go func() {
		err := runServeWith(ctx, cfg, &stdout, &stderr, nil)
		fmt.Fprintln(&stderr, err)
		result <- err
	}()
	addr := waitServePrefix(t, &stdout, &stderr, "listening http ")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /health/live HTTP/1.1\r\nHost: lab\r\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want shutdown deadline failure, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown exceeded bounded grace")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("stalled HTTP connection not closed: %v", err)
	}
}

func TestHTTPShutdownMarksUnreadyAndEndsRESTStream(t *testing.T) {
	doc, err := config.Parse([]byte(`schema_version: 2
server: {admin_only: true}
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  http: {enabled: true, bind: "127.0.0.1:0"}
api:
  bootstrap_tokens:
    - id: lab
      token: {file: /test/token}
      scopes: [events:read]
`))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(config.SecretRef) ([]byte, error) { return []byte("test-bootstrap-token-at-least-32-bytes"), nil }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	ring := events.New(8, nil)
	defer ring.Close()
	hs, ln, err := startHTTP("", doc, mgr, lookup, nil, ring, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	go func() { _ = hs.Serve(ln) }()
	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer test-bootstrap-token-at-least-32-bytes")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("stream status %d: %s", resp.StatusCode, data)
	}
	hs.beginShutdown()
	// Exercise the readiness handler directly while accepted connections drain.
	rec := httptest.NewRecorder()
	hs.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready during shutdown: %d %s", rec.Code, rec.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Fatalf("stream prevented graceful shutdown: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatal(err)
	}
	// Repeated calls cannot double-close the shared cancellation channel.
	hs.beginShutdown()
}

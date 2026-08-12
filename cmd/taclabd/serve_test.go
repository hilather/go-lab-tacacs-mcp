package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestServeLegacyAndShutdown(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "secret")
	if err := os.WriteFile(sec, []byte("LabSecret-16chars!"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 1
server:
  shutdown_grace: 1s
listeners:
  legacy_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: loop
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	errc := make(chan int, 1)
	go func() { errc <- serve(ctx, []string{"--config", cfg}, &stdout, &stderr) }()

	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "ready") {
			for _, line := range strings.Split(stdout.String(), "\n") {
				if strings.HasPrefix(line, "listening legacy_tacacs ") {
					addr = strings.TrimPrefix(line, "listening legacy_tacacs ")
				}
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("serve did not become ready: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	c, err := tclient.Dial(addr, []byte("LabSecret-16chars!"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	cancel()
	select {
	case code := <-errc:
		if code != 0 {
			t.Fatalf("exit %d stderr=%q", code, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestServeMissingConfigFile(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := serve(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d want 1 stderr=%q", code, stderr.String())
	}
}

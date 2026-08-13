package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
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
observability:
  metrics: {enabled: false}
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
	var stdout, stderr syncBuf
	errc := make(chan int, 1)
	go func() { errc <- serve(ctx, []string{"--config", cfg}, &stdout, &stderr) }()

	addr := waitServeAddr(t, &stdout, &stderr)

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

func TestServeInFlightSurvivesCancel(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "secret")
	if err := os.WriteFile(sec, []byte("LabSecret-16chars!"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 1
server:
  shutdown_grace: 2s
listeners:
  legacy_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
observability:
  metrics: {enabled: false}
clients:
  - id: loop
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	h := &holdStartHandler{started: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan error, 1)
	go func() { errc <- runServeWith(ctx, cfg, &stdout, &stderr, h) }()

	addr := waitServeAddr(t, &stdout, &stderr)
	c, err := tclient.Dial(addr, []byte("LabSecret-16chars!"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, body); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler not started")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(h.release)
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.StatusGetUser {
		t.Fatalf("status=%#x want GETUSER during drain", rep.Status)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve: %v stderr=%q", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func waitServeAddr(t *testing.T, stdout, stderr *syncBuf) string {
	t.Helper()
	return waitServePrefix(t, stdout, stderr, "listening legacy_tacacs ")
}

func waitServePrefix(t *testing.T, stdout, stderr *syncBuf, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out := stdout.String()
		if strings.Contains(out, "ready") {
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, prefix) {
					return strings.TrimPrefix(line, prefix)
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("serve did not become ready: stdout=%q stderr=%q", stdout.String(), stderr.String())
	return ""
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type holdStartHandler struct {
	server.Stub
	started chan struct{}
	release chan struct{}
}

func (h *holdStartHandler) AuthenStart(ctx context.Context, _ server.Env, _ codec.AuthenStart) (codec.AuthenReply, error) {
	select {
	case <-h.started:
	default:
		close(h.started)
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return codec.AuthenReply{Status: codec.AuthenStatusError}, ctx.Err()
	}
	return codec.AuthenReply{Status: codec.AuthenStatusGetUser}, nil
}

func TestServeTLSOnlyPlaintextRejected(t *testing.T) {
	pki, err := tacacstls.GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "lab.yaml")
	src := `
schema_version: 1
server:
  shutdown_grace: 1s
listeners:
  legacy_tacacs: {enabled: false}
  secure_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    handshake_timeout: 2s
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
    tls:
      minimum_version: TLS1.3
      identities:
        default_id: lab-default
        profiles:
          - id: lab-default
            server_names: [tacacs.lab.example]
            certificate_chain: {file: ` + pki.ServerChain + `}
            private_key: {file: ` + pki.ServerKey + `}
      client_authentication: require_and_verify_certificate
      client_ca_bundle: {file: ` + pki.ClientCACert + `}
      revocation:
        mode: configured_crl
        crl_bundle: {file: ` + pki.CRLEmpty + `}
      session_resumption:
        enabled: true
        ticket_lifetime: 168h
      reject_early_data: true
  http: {enabled: false}
observability:
  metrics: {enabled: false}
clients:
  - id: nas
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8"]
      transports: [tls]
      certificate:
        dns_sans: [nas.lab.example]
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan error, 1)
	go func() { errc <- runServeWith(ctx, cfg, &stdout, &stderr, nil) }()
	addr := waitServePrefix(t, &stdout, &stderr, "listening secure_tacacs ")

	nc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = nc.SetDeadline(time.Now().Add(time.Second))
	body, _ := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagUnencrypted, SessionID: 1}
	pkt := append(h.Encode(), body...)
	_, _ = nc.Write(pkt)
	buf := make([]byte, 32)
	n, _ := nc.Read(buf)
	_ = nc.Close()
	if n >= 12 && (buf[0] == 0xc0 || buf[0] == 0xc1) {
		t.Fatalf("plaintext TACACS accepted on TLS port: %x", buf[:n])
	}

	crt, err := tls.LoadX509KeyPair(pki.ClientOKCert, pki.ClientOKKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(pki.ServerCACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{crt},
		RootCAs:      roots,
		ServerName:   "tacacs.lab.example",
	}
	c, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tclient.New(c, nil)
	if err := tc.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tc.ReadPacket(); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve: %v stderr=%q", err, stderr.String())
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

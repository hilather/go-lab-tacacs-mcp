package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func labYAML(p *LabPKI, bind string, extraProfiles string, extraClients string) string {
	if extraProfiles == "" {
		extraProfiles = ""
	}
	return fmt.Sprintf(`
schema_version: 1
server:
  shutdown_grace: 1s
listeners:
  legacy_tacacs: {enabled: false}
  secure_tacacs:
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
    tls:
      minimum_version: TLS1.3
      identities:
        default_id: lab-default
        require_sni: false
        profiles:
          - id: lab-default
            server_names: [tacacs.lab.example]
            certificate_chain: {file: %q}
            private_key: {file: %q}
%s
      client_authentication: require_and_verify_certificate
      client_ca_bundle: {file: %q}
      revocation:
        mode: configured_crl
        crl_bundle: {file: %q}
      session_resumption:
        enabled: true
        ticket_lifetime: 168h
        recheck_client_revocation: true
      reject_early_data: true
  http: {enabled: false}
clients:
  - id: nas
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8", "::1/128"]
      transports: [tls]
      certificate:
        dns_sans: [nas.lab.example]
  - id: nas-ip
    priority: 20
    match:
      source_cidrs: ["127.0.0.0/8", "::1/128"]
      transports: [tls]
      certificate:
        ip_sans: ["127.0.0.1"]
%s
`, bind, p.ServerChain, p.ServerKey, extraProfiles, p.ClientCACert, p.CRLEmpty, extraClients)
}

func startTLS(t testing.TB, yaml string, h server.Handler) (*Listener, *state.Manager, *LabPKI) {
	t.Helper()
	doc, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(doc); err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = server.Stub{}
	}
	ln, err := Listen(Options{
		Bind:     doc.Listeners.SecureTACACS.Bind,
		Settings: doc.Listeners.SecureTACACS,
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
	return ln, mgr, nil
}

func startDefault(t testing.TB) (*Listener, *LabPKI) {
	t.Helper()
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, _, _ := startTLS(t, labYAML(pki, "127.0.0.1:0", "", ""), nil)
	return ln, pki
}

func clientTLS(t testing.TB, pki *LabPKI, cert, key string, serverName string, cache tls.ClientSessionCache) *tls.Config {
	t.Helper()
	crt, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(pki.ServerCACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("server CA")
	}
	if serverName == "" {
		serverName = "tacacs.lab.example"
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{crt},
		RootCAs:            roots,
		ServerName:         serverName,
		ClientSessionCache: cache,
	}
}

func dialAuth(t testing.TB, addr string, cfg *tls.Config) *tclient.Conn {
	t.Helper()
	d := &tls.Dialer{Config: cfg, NetDialer: nil}
	nc, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	return tclient.New(nc, nil)
}

func authorPacket() (tcodec.Header, []byte) {
	body, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		panic(err)
	}
	h := tcodec.Header{
		Version:   tcodec.VersionByte(0),
		Type:      tcodec.TypeAuthor,
		SeqNo:     1,
		Flags:     tcodec.FlagUnencrypted | tcodec.FlagSingleConnect,
		SessionID: 1,
	}
	return h, body
}

func mustHandshake(t testing.TB, addr string, cfg *tls.Config) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	return c
}

// handshakeMustFail reports whether the server rejected the peer. TLS 1.3
// clients can return from Dial/Handshake before the server's VerifyConnection
// alert arrives, so a successful Dial is not evidence of acceptance.
func handshakeMustFail(t testing.TB, addr string, cfg *tls.Config) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return
	}
	defer c.Close()
	tc := tclient.New(c, nil)
	tc.SetDeadlines(time.Second)
	h, body := authorPacket()
	if err := tc.WritePacket(h, body); err != nil {
		return
	}
	if _, _, err := tc.ReadPacket(); err != nil {
		return
	}
	t.Fatal("tls handshake was accepted")
}

func receiveSessionTicket(t testing.TB, c *tls.Conn) {
	t.Helper()
	// TLS 1.3 NewSessionTicket is post-handshake; a short read pulls it in.
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = c.Read(make([]byte, 1))
	_ = c.SetReadDeadline(time.Time{})
}

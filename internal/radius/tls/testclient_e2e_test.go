package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	tctls "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/tls"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	labSecret          = "LabRadius-Secret-32-bytes-ok!!"
	accessTestPassword = "labpass1!"
)

func TestIndependentTestclientPAPOnRadSec(t *testing.T) {
	t.Parallel()
	ln, _ := startRadSecPolicy(t)
	cfg := clientTLS(t, ln.pki)
	c, err := tctls.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0xa1
	pap, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    11,
		Authenticator: ra,
		UserName:      "lab-admin",
		Password:      []byte(accessTestPassword),
		IncludeMA:     true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(pap); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("independent client rejected Access reply: %v", err)
	}
	if reply.Code != tcodec.AccessAccept {
		t.Fatalf("code=%s", reply.Code)
	}
	if reply.Identifier != 11 {
		t.Fatalf("id=%d", reply.Identifier)
	}
	if len(reply.Attrs) == 0 || reply.Attrs[0].Type != tcodec.TypeMessageAuthenticator {
		t.Fatalf("MA first: %+v", reply.Attrs)
	}
}

func TestUnknownClientCertClosesWithoutReply(t *testing.T) {
	t.Parallel()
	ln, _ := startRadSecPolicy(t)
	cfg := unknownClientTLS(t, ln.pki)
	c, err := tctls.Dial(ln.Addr().String(), cfg)
	if err == nil {
		defer c.Close()
		secret := []byte(labSecret)
		var ra [16]byte
		ra[0] = 0xb2
		pap, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
			Identifier:    3,
			Authenticator: ra,
			UserName:      "lab-admin",
			Password:      []byte(accessTestPassword),
			IncludeMA:     true,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.WritePacket(pap)
		if _, err := c.ReadPacket(); err == nil {
			t.Fatal("unknown client must not receive a RADIUS reply")
		}
	}
}

func TestIndependentTestclientAccountingOnRadSec(t *testing.T) {
	t.Parallel()
	ln, _ := startRadSecPolicy(t)
	cfg := clientTLS(t, ln.pki)
	c, err := tctls.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	secret := []byte(labSecret)
	acctReq, err := testclient.EncodeAccountingRequest(secret, testclient.AccountingRequest{
		Identifier: 12,
		StatusType: testclient.AcctStart,
		SessionID:  "radsec-1",
		IncludeMA:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := tcodec.Decode(acctReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(acctReq); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := testclient.DecodeAccountingResponse(secret, pkt.Authenticator, got)
	if err != nil {
		t.Fatalf("independent client rejected Accounting-Response: %v", err)
	}
	if reply.Identifier != 12 {
		t.Fatalf("id=%d", reply.Identifier)
	}
}

func TestRadSecRejectsTLS12Client(t *testing.T) {
	t.Parallel()
	ln, _ := startRadSecPolicy(t)
	cfg := clientTLS(t, ln.pki)
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS12
	_, err := tctls.Dial(ln.Addr().String(), cfg)
	if err == nil {
		t.Fatal("TLS 1.2 client must not complete a RadSec handshake")
	}
}

func TestTLSOnlyClientHasNoUDPEndpoint(t *testing.T) {
	t.Parallel()
	_, mgr := startRadSecPolicy(t)
	c, ok := mgr.Snapshot().Client("radsec")
	if !ok {
		t.Fatal("missing client")
	}
	for _, ep := range c.Client.Endpoints {
		if ep.Protocol == domain.ProtocolRADIUS && ep.Transport == config.EndpointTransportUDP {
			t.Fatal("TLS-only fixture must not expose a UDP RADIUS endpoint for DAC")
		}
	}
}

type radSecLab struct {
	*Listener
	pki labPKI
}

func startRadSecPolicy(t *testing.T) (*radSecLab, *state.Manager) {
	t.Helper()
	dir := t.TempDir()
	pki := generateLabPKI(t, dir)
	sec := filepath.Join(dir, "radius.secret")
	if err := os.WriteFile(sec, []byte(labSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	phc, err := credentials.DeriveArgon2id([]byte(accessTestPassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(login, phc, 0o600); err != nil {
		t.Fatal(err)
	}
	src := radSecYAML(pki, sec, login)
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := aaa.New(aaa.Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  events.New(8, domain.SystemClock{}),
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := doc.Listeners.RADIUSRadSec
	settings.Enabled = true
	ln, err := Listen(Options{
		Bind:     "127.0.0.1:0",
		Required: true,
		Settings: settings,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Access:   server.Access{AAA: svc},
		Recorder: svc,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !ln.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ln.Ready() {
		t.Fatal("listener not ready")
	}
	t.Cleanup(func() {
		cancel()
		_ = ln.Drain(context.Background())
		_ = ln.Close()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
		}
	})
	return &radSecLab{Listener: ln, pki: pki}, mgr
}

func clientTLS(t *testing.T, p labPKI) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.ClientCert, p.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(p.ServerChain)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("server roots")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   "radsec.lab.example",
	}
}

func unknownClientTLS(t *testing.T, p labPKI) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.UnknownCert, p.UnknownKey)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(p.ServerChain)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("server roots")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   "radsec.lab.example",
	}
}

func radSecYAML(p labPKI, secret, login string) string {
	return `
schema_version: 2
server:
  admin_only: true
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access: {enabled: false}
    accounting: {enabled: false}
    radsec:
      enabled: true
      bind: 127.0.0.1:0
      max_connections: 16
      idle_timeout: 30s
      handshake_timeout: 5s
      tls:
        minimum_version: TLS1.3
        client_authentication: require_and_verify_certificate
        reject_early_data: true
        client_ca_bundle: {file: ` + p.ClientCA + `}
        revocation:
          mode: configured_crl
          crl_bundle: {file: ` + p.CRL + `}
        session_resumption:
          enabled: true
          ticket_lifetime: 168h
          recheck_client_revocation: true
        identities:
          default_id: radsec
          profiles:
            - id: radsec
              server_names: [radsec.lab.example]
              certificate_chain: {file: ` + p.ServerChain + `}
              private_key: {file: ` + p.ServerKey + `}
clients:
  - id: radsec
    priority: 10
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access, accounting]
        radius:
          shared_secret: {file: ` + secret + `}
          access_policy_id: default-radius-access
groups:
  - id: lab-admins
    priority: 10
users:
  - id: lab-admin
    group_ids: [lab-admins]
    credentials:
      login:
        verifier: {file: ` + login + `}
radius_reply_profiles:
  - id: lab-accept
    attributes:
      - name: Session-Timeout
        value: "600"
radius_policies:
  - id: default-radius-access
    rules:
      - id: permit-lab-admins
        match:
          groups_any: [lab-admins]
        effect: permit
        reply_profiles: [lab-accept]
`
}

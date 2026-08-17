package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	radiusserver "github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
)

func TestLoadPEAPCertificateEmpty(t *testing.T) {
	t.Parallel()
	cert, ok, err := loadPEAPCertificate(&config.Document{}, nil)
	if err != nil || ok || len(cert.Certificate) != 0 {
		t.Fatalf("empty doc must not mint: ok=%v err=%v certs=%d", ok, err, len(cert.Certificate))
	}
	_, ok, err = loadPEAPCertificate(nil, nil)
	if err != nil || ok {
		t.Fatalf("nil doc: ok=%v err=%v", ok, err)
	}
}

func TestLoadPEAPCertificateUsesRadSecThenSecureTLS(t *testing.T) {
	t.Parallel()
	radsecPKI, err := tacacstls.GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	securePKI, err := tacacstls.GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }

	radsec := config.Document{Listeners: config.Listeners{
		RADIUSRadSec: config.RADIUSRadSecListener{TLS: labTLS(radsecPKI, "radsec-default")},
	}}
	radsecCert, ok, err := loadPEAPCertificate(&radsec, lookup)
	if err != nil || !ok || radsecCert.Leaf == nil || radsecCert.Leaf.Subject.CommonName == "" {
		t.Fatalf("radsec: ok=%v err=%v leaf=%v", ok, err, radsecCert.Leaf)
	}

	secure := config.Document{Listeners: config.Listeners{
		SecureTACACS: config.SecureTACACSListener{TLS: labTLS(securePKI, "tacacs-default")},
	}}
	secureCert, ok, err := loadPEAPCertificate(&secure, lookup)
	if err != nil || !ok {
		t.Fatalf("secure tls: ok=%v err=%v", ok, err)
	}
	if bytes.Equal(radsecCert.Certificate[0], secureCert.Certificate[0]) {
		t.Fatal("fixture PKIs must differ so preference is observable")
	}

	both := config.Document{Listeners: config.Listeners{
		RADIUSRadSec: config.RADIUSRadSecListener{TLS: labTLS(radsecPKI, "radsec-default")},
		SecureTACACS: config.SecureTACACSListener{TLS: labTLS(securePKI, "tacacs-default")},
	}}
	pref, ok, err := loadPEAPCertificate(&both, lookup)
	if err != nil || !ok {
		t.Fatalf("prefer radsec: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(pref.Certificate[0], radsecCert.Certificate[0]) {
		t.Fatal("radsec default must win over SecureTACACS")
	}
}

func TestLoadPEAPCertificateMissingKeyFailsClosed(t *testing.T) {
	t.Parallel()
	pki, err := tacacstls.GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc := &config.Document{Listeners: config.Listeners{
		RADIUSRadSec: config.RADIUSRadSecListener{TLS: config.SecureTLS{
			Identities: config.TLSIdentities{
				DefaultID: "missing",
				Profiles: []config.TLSProfile{{
					ID:               "missing",
					CertificateChain: config.FileRef{File: pki.ServerChain},
					PrivateKey:       config.SecretRef{File: filepath.Join(t.TempDir(), "no-such-key")},
				}},
			},
		}},
	}}
	_, ok, err := loadPEAPCertificate(doc, func(ref config.SecretRef) ([]byte, error) {
		return os.ReadFile(ref.File)
	})
	if err == nil || ok {
		t.Fatal("missing key must fail closed")
	}
}

func TestAttachPEAPLeavesUnsetWithoutIdentity(t *testing.T) {
	t.Parallel()
	access, err := attachPEAP(radiusserver.Access{}, &config.Document{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if access.PEAP != nil || access.Tunnels != nil {
		t.Fatal("must not invent a PEAP server without a TLS identity")
	}
}

func TestServePEAPUsesConfiguredIdentity(t *testing.T) {
	pki, err := tacacstls.GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "radius")
	if err := os.WriteFile(secret, []byte("LabRadius-Secret-32-bytes-ok!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 2
server:
  shutdown_grace: 1s
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access:
      enabled: true
      required: true
      bind: 127.0.0.1:0
    accounting: {enabled: false}
    radsec:
      enabled: false
      tls:
        identities:
          default_id: lab-default
          profiles:
            - id: lab-default
              server_names: [tacacs.lab.example]
              certificate_chain: {file: ` + pki.ServerChain + `}
              private_key: {file: ` + pki.ServerKey + `}
  http: {enabled: false}
observability:
  metrics: {enabled: false}
clients:
  - id: loop
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: ` + secret + `}
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [peap]
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan error, 1)
	go func() { errc <- runServeWith(ctx, cfg, &stdout, &stderr, nil) }()
	addr := waitServePrefix(t, &stdout, &stderr, "listening radius_access ")
	reply := servePEAPIdentity(t, addr)
	if reply.Code != tcodec.AccessChallenge {
		t.Fatalf("code=%s stderr=%q", reply.Code, stderr.String())
	}
	if _, ok := testclient.FirstState(reply.Attrs); !ok {
		t.Fatal("missing State")
	}
	eap, err := testclient.FirstEAP(reply.Attrs)
	if err != nil || eap.Code != testclient.EAPCodeRequest || eap.Type != testclient.EAPTypePEAP {
		t.Fatalf("eap=%+v err=%v", eap, err)
	}
	if len(eap.Data) < 1 || eap.Data[0] != 0x20 {
		t.Fatalf("want PEAPv0 Start, data=%x", eap.Data)
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

func TestServePEAPWithoutIdentityRejects(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "radius")
	if err := os.WriteFile(secret, []byte("LabRadius-Secret-32-bytes-ok!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 2
server:
  shutdown_grace: 1s
listeners:
  tacacs:
    legacy: {enabled: false}
    tls: {enabled: false}
  radius:
    access:
      enabled: true
      required: true
      bind: 127.0.0.1:0
    accounting: {enabled: false}
  http: {enabled: false}
observability:
  metrics: {enabled: false}
clients:
  - id: loop
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: ` + secret + `}
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [peap]
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan error, 1)
	go func() { errc <- runServeWith(ctx, cfg, &stdout, &stderr, nil) }()
	addr := waitServePrefix(t, &stdout, &stderr, "listening radius_access ")
	reply := servePEAPIdentity(t, addr)
	if reply.Code != tcodec.AccessReject {
		t.Fatalf("code=%s want Reject (no minted cert) stderr=%q", reply.Code, stderr.String())
	}
	if _, ok := testclient.FirstState(reply.Attrs); ok {
		t.Fatal("Reject must not leak State")
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

func labTLS(pki *tacacstls.LabPKI, id string) config.SecureTLS {
	return config.SecureTLS{
		Identities: config.TLSIdentities{
			DefaultID: id,
			Profiles: []config.TLSProfile{{
				ID:               id,
				ServerNames:      []string{"tacacs.lab.example"},
				CertificateChain: config.FileRef{File: pki.ServerChain},
				PrivateKey: config.SecretRef{
					Purpose: credentials.PurposeTLSPrivateKey,
					File:    pki.ServerKey,
				},
			}},
		},
	}
}

func servePEAPIdentity(t *testing.T, addr string) testclient.AccessReply {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	secret := []byte("LabRadius-Secret-32-bytes-ok!!")
	var ra [16]byte
	ra[0] = 0xc1
	req, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    7,
		Authenticator: ra,
		UserName:      "lab-admin",
		IncludeMA:     true,
		Extra: []tcodec.Attr{
			testclient.EAPMessageAttr(testclient.EAPIdentityResponse(1, "lab-admin")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return reply
}

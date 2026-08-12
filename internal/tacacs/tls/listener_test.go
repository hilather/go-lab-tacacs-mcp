package tls

import (
	"net"
	"strings"
	"testing"
	"time"

	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestMTLSRoundTrip(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	rh, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if rh.Flags&tcodec.FlagUnencrypted == 0 {
		t.Fatalf("reply missing UNENCRYPTED flag: %#x", rh.Flags)
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorFail {
		t.Fatalf("status=%#x", rep.Status)
	}
}

func TestIPSANMatch(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientIPCert, pki.ClientIPKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestUnauthorizedValidCertRejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientUnauthCert, pki.ClientUnauthKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestMissingClientCertRejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	cfg.Certificates = nil
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestUnknownCARejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientUnknownCert, pki.ClientUnknownKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestExpiredClientRejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientExpiredCert, pki.ClientExpiredKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestFutureClientRejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientFutureCert, pki.ClientFutureKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestWrongEKURejected(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientWrongEKUCert, pki.ClientWrongEKUKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestRevokedClientRejected(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", `
  - id: revoked
    priority: 30
    match:
      source_cidrs: ["127.0.0.0/8"]
      transports: [tls]
      certificate:
        dns_sans: [revoked.lab.example]
`)
	// Point the listener at the revoked CRL.
	docYAML := strings.Replace(yaml, pki.CRLEmpty, pki.CRLRevoked, 1)
	ln, _, _ := startTLS(t, docYAML, nil)
	cfg := clientTLS(t, pki, pki.ClientRevokedCert, pki.ClientRevokedKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestIPv6Match(t *testing.T) {
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	_ = ln6.Close()

	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, _, _ := startTLS(t, labYAML(pki, "[::1]:0", "", ""), nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestNonSingleConnectCloses(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = strings.Replace(yaml, "enabled: true\n      max_lifetime: 1m", "enabled: false\n      max_lifetime: 1m", 1)
	ln, _, _ := startTLS(t, yaml, nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	h, body := authorPacket()
	h.Flags = tcodec.FlagUnencrypted
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	c.SetDeadlines(400 * time.Millisecond)
	h2, body2 := authorPacket()
	h2.SessionID = 2
	h2.Flags = tcodec.FlagUnencrypted
	_ = c.WritePacket(h2, body2)
	_, _, err = c.ReadPacket()
	if err == nil {
		t.Fatal("non-single-connect must close after the first session")
	}
}

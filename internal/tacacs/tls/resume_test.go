package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSessionResumption(t *testing.T) {
	ln, pki := startDefault(t)
	cache := tls.NewLRUClientSessionCache(8)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", cache)
	c1 := mustHandshake(t, ln.Addr().String(), cfg)
	if c1.ConnectionState().DidResume {
		t.Fatal("first handshake must be full")
	}
	receiveSessionTicket(t, c1)
	_ = c1.Close()

	c2 := mustHandshake(t, ln.Addr().String(), cfg)
	if !c2.ConnectionState().DidResume {
		t.Fatal("second handshake must resume")
	}
}

func TestResumptionDisabled(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = replaceResumption(yaml, false, "0s")
	ln, _, _ := startTLS(t, yaml, nil)
	cache := tls.NewLRUClientSessionCache(8)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", cache)
	c1 := mustHandshake(t, ln.Addr().String(), cfg)
	_ = c1.Close()
	c2 := mustHandshake(t, ln.Addr().String(), cfg)
	if c2.ConnectionState().DidResume {
		t.Fatal("resumption must stay off when disabled")
	}
}

func TestResumeRechecksRevocation(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, _, _ := startTLS(t, labYAML(pki, "127.0.0.1:0", "", ""), nil)
	cache := tls.NewLRUClientSessionCache(8)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", cache)
	c1 := mustHandshake(t, ln.Addr().String(), cfg)
	receiveSessionTicket(t, c1)
	_ = c1.Close()

	if err := writeRevokingCRL(pki.CRLEmpty, pki.ClientCACert, pki.ClientCAKey, pki.ClientOKCert); err != nil {
		t.Fatal(err)
	}
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func TestTicketLifetimeZeroDisables(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = replaceResumption(yaml, true, "0s")
	ln, _, _ := startTLS(t, yaml, nil)
	cache := tls.NewLRUClientSessionCache(4)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", cache)
	c1 := mustHandshake(t, ln.Addr().String(), cfg)
	_ = c1.Close()
	c2 := mustHandshake(t, ln.Addr().String(), cfg)
	if c2.ConnectionState().DidResume {
		t.Fatal("ticket_lifetime 0 must disable tickets")
	}
}

func replaceResumption(yaml string, enabled bool, life string) string {
	old := "session_resumption:\n        enabled: true\n        ticket_lifetime: 168h"
	en := "true"
	if !enabled {
		en = "false"
	}
	new := "session_resumption:\n        enabled: " + en + "\n        ticket_lifetime: " + life
	return strings.Replace(yaml, old, new, 1)
}

func writeRevokingCRL(path, caCert, caKey, revokedCert string) error {
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(caKey)
	if err != nil {
		return err
	}
	leafPEM, err := os.ReadFile(revokedCert)
	if err != nil {
		return err
	}
	ca, err := parseOneCert(caPEM)
	if err != nil {
		return err
	}
	leaf, err := parseOneCert(leafPEM)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	pemBytes, err := makeCRL(ca, key, []*x509.Certificate{leaf}, time.Now())
	if err != nil {
		return err
	}
	return os.WriteFile(path, pemBytes, 0o644)
}

func parseOneCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	return x509.ParseCertificate(block.Bytes)
}

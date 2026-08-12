package tls

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWrongIssuerCRLDoesNotAdmit(t *testing.T) {
	pki, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateLabPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	otherCA, err := parseOneCertFile(other.ClientCACert)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := parseECKeyFile(other.ClientCAKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCRL, err := makeCRL(otherCA, otherKey, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(pki.Dir, "wrong-ca-crl.pem")
	if err := os.WriteFile(wrongPath, wrongCRL, 0o644); err != nil {
		t.Fatal(err)
	}
	yaml := labYAML(pki, "127.0.0.1:0", "", "")
	yaml = strings.Replace(yaml, pki.CRLEmpty, wrongPath, 1)
	ln, _, _ := startTLS(t, yaml, nil)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	handshakeMustFail(t, ln.Addr().String(), cfg)
}

func parseOneCertFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	return x509.ParseCertificate(block.Bytes)
}

func parseECKeyFile(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	return x509.ParseECPrivateKey(block.Bytes)
}

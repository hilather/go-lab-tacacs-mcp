package peap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestNewServerRequiresCertificate(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(tls.Certificate{}); err == nil {
		t.Fatal("empty cert")
	}
}

func TestNewServerTLS13Only(t *testing.T) {
	t.Parallel()
	s, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.TLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("min=%d max=%d", cfg.MinVersion, cfg.MaxVersion)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session tickets must stay off until resumption is in scope")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("certs=%d", len(cfg.Certificates))
	}
}

func TestHandshakeWithClientReturnsTLS13ServerRecords(t *testing.T) {
	t.Parallel()
	s, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.HandshakeWithClient()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) < 5 || rec[0] != 0x16 {
		t.Fatalf("want TLS handshake record, got %x", rec[:min(8, len(rec))])
	}
	// TLS 1.3 still writes record version 1.2 (0x0303) on the wire.
	if rec[1] != 0x03 || rec[2] != 0x03 {
		t.Fatalf("record version %x %x", rec[1], rec[2])
	}
}

func TestHandshakeWithClientDrivesShippedNewServer(t *testing.T) {
	t.Parallel()
	s, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.HandshakeWithClient(); err != nil {
		t.Fatal(err)
	}
}

func mustPEAPCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "peap.lab.example"},
		DNSNames:              []string{"peap.lab.example"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

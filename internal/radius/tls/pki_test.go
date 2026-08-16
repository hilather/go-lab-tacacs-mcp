package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type labPKI struct {
	ServerChain string
	ServerKey   string
	ClientCA    string
	ClientCert  string
	ClientKey   string
	UnknownCert string
	UnknownKey  string
	CRL         string
}

func generateLabPKI(t *testing.T, dir string) labPKI {
	t.Helper()
	now := time.Now().UTC()
	serverCA, serverCAKey := mustCA(t, "RadSec Server Root", now)
	server, serverKey := mustLeaf(t, leafReq{
		cn: "radsec.lab.example", dns: []string{"radsec.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ca:  serverCA, caKey: serverCAKey, now: now,
	})
	clientCA, clientCAKey := mustCA(t, "RadSec Client Root", now)
	client, clientKey := mustLeaf(t, leafReq{
		cn: "nas.lab.example", dns: []string{"nas.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now,
	})
	unkCA, unkCAKey := mustCA(t, "Unknown Client Root", now)
	unknown, unknownKey := mustLeaf(t, leafReq{
		cn: "unknown.lab.example", dns: []string{"unknown.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  unkCA, caKey: unkCAKey, now: now,
	})
	crl := mustCRL(t, clientCA, clientCAKey, now)
	p := labPKI{
		ServerChain: filepath.Join(dir, "server-chain.pem"),
		ServerKey:   filepath.Join(dir, "server.key"),
		ClientCA:    filepath.Join(dir, "client-ca.pem"),
		ClientCert:  filepath.Join(dir, "client-ok.pem"),
		ClientKey:   filepath.Join(dir, "client-ok.key"),
		UnknownCert: filepath.Join(dir, "client-unknown.pem"),
		UnknownKey:  filepath.Join(dir, "client-unknown.key"),
		CRL:         filepath.Join(dir, "client-crl.pem"),
	}
	writePEM(t, p.ServerChain, "CERTIFICATE", append(encodeCert(server), encodeCert(serverCA)...))
	writeKey(t, p.ServerKey, serverKey)
	writePEM(t, p.ClientCA, "CERTIFICATE", encodeCert(clientCA))
	writePEM(t, p.ClientCert, "CERTIFICATE", encodeCert(client))
	writeKey(t, p.ClientKey, clientKey)
	writePEM(t, p.UnknownCert, "CERTIFICATE", encodeCert(unknown))
	writeKey(t, p.UnknownKey, unknownKey)
	if err := os.WriteFile(p.CRL, crl, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type leafReq struct {
	cn    string
	dns   []string
	eku   []x509.ExtKeyUsage
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	now   time.Time
}

func mustCA(t *testing.T, cn string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustLeaf(t *testing.T, req leafReq) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(req.now.UnixNano() + 1),
		Subject:               pkix.Name{CommonName: req.cn},
		NotBefore:             req.now.Add(-time.Hour),
		NotAfter:              req.now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           req.eku,
		DNSNames:              req.dns,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, req.ca, &key.PublicKey, req.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustCRL(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, now time.Time) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func encodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if typ == "CERTIFICATE" {
		if err := os.WriteFile(path, der, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LabPKI is a generated lab certificate tree. Private keys are written
// only to dir; they must not be committed (secret-scan rejects PEM keys).
type LabPKI struct {
	Dir string

	ServerCACert, ServerCAKey                     string
	ServerIntermediateCert, ServerIntermediateKey string
	ServerChain, ServerKey                        string
	ServerAltChain, ServerAltKey                  string
	ServerWildcardChain, ServerWildcardKey        string

	ClientCACert, ClientCAKey             string
	ClientOKCert, ClientOKKey             string
	ClientIPCert, ClientIPKey             string
	ClientUnauthCert, ClientUnauthKey     string
	ClientExpiredCert, ClientExpiredKey   string
	ClientFutureCert, ClientFutureKey     string
	ClientRevokedCert, ClientRevokedKey   string
	ClientWrongEKUCert, ClientWrongEKUKey string
	ClientUnknownCert, ClientUnknownKey   string

	CRLEmpty   string
	CRLRevoked string
}

// GenerateLabPKI writes a lab PKI under dir. Identities:
//
//	server: tacacs.lab.example (chain via intermediate)
//	server-alt: other.tacacs.lab.example
//	server-wildcard: *.tacacs.lab.example
//	client-ok: nas.lab.example
//	client-ip: 127.0.0.1
//	client-unauth: other.lab.example
type GenerateLabPKIOption func(*labPKIOpts)

type labPKIOpts struct {
	now time.Time
}

// WithPKITime fixes NotBefore/NotAfter relative to now (tests).
func WithPKITime(now time.Time) GenerateLabPKIOption {
	return func(o *labPKIOpts) { o.now = now }
}

// GenerateLabPKI materializes the reference lab certificate set.
func GenerateLabPKI(dir string, opts ...GenerateLabPKIOption) (*LabPKI, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	o := labPKIOpts{now: time.Now().UTC()}
	for _, fn := range opts {
		fn(&o)
	}
	now := o.now

	serverCA, serverCAKey, err := makeCA("TacLab Server Root", now, now.Add(10*365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	inter, interKey, err := makeIntermediate("TacLab Server Intermediate", serverCA, serverCAKey, now, now.Add(5*365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	server, serverKey, err := makeLeaf(leafReq{
		cn: "tacacs.lab.example", dns: []string{"tacacs.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ca:  inter, caKey: interKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	alt, altKey, err := makeLeaf(leafReq{
		cn: "other.tacacs.lab.example", dns: []string{"other.tacacs.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ca:  inter, caKey: interKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	wild, wildKey, err := makeLeaf(leafReq{
		cn: "wildcard.tacacs.lab.example", dns: []string{"*.tacacs.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ca:  inter, caKey: interKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	clientCA, clientCAKey, err := makeCA("TacLab Client Root", now, now.Add(10*365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	ok, okKey, err := makeLeaf(leafReq{
		cn: "nas.lab.example", dns: []string{"nas.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	ip, ipKey, err := makeLeaf(leafReq{
		cn: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	unauth, unauthKey, err := makeLeaf(leafReq{
		cn: "other.lab.example", dns: []string{"other.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	expired, expiredKey, err := makeLeaf(leafReq{
		cn: "expired.lab.example", dns: []string{"expired.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now.Add(-400 * 24 * time.Hour), until: now.Add(-24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	future, futureKey, err := makeLeaf(leafReq{
		cn: "future.lab.example", dns: []string{"future.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now.Add(24 * time.Hour), until: now.Add(400 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	revoked, revokedKey, err := makeLeaf(leafReq{
		cn: "revoked.lab.example", dns: []string{"revoked.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  clientCA, caKey: clientCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	wrong, wrongKey, err := makeLeaf(leafReq{
		cn: "wrong-eku.lab.example", dns: []string{"wrong-eku.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ca:  clientCA, caKey: clientCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}
	unkCA, unkCAKey, err := makeCA("Unknown Client Root", now, now.Add(10*365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	unknown, unknownKey, err := makeLeaf(leafReq{
		cn: "unknown.lab.example", dns: []string{"unknown.lab.example"},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ca:  unkCA, caKey: unkCAKey, now: now, until: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		return nil, err
	}

	emptyCRL, err := makeCRL(clientCA, clientCAKey, nil, now)
	if err != nil {
		return nil, err
	}
	revCRL, err := makeCRL(clientCA, clientCAKey, []*x509.Certificate{revoked}, now)
	if err != nil {
		return nil, err
	}

	p := &LabPKI{Dir: dir}
	writes := []struct {
		rel  string
		dest *string
		pem  []byte
		mode os.FileMode
	}{
		{"server-ca.pem", &p.ServerCACert, encodeCert(serverCA), 0o644},
		{"server-ca.key", &p.ServerCAKey, encodeKey(serverCAKey), 0o600},
		{"server-intermediate.pem", &p.ServerIntermediateCert, encodeCert(inter), 0o644},
		{"server-intermediate.key", &p.ServerIntermediateKey, encodeKey(interKey), 0o600},
		{"server-chain.pem", &p.ServerChain, append(encodeCert(server), encodeCert(inter)...), 0o644},
		{"server.key", &p.ServerKey, encodeKey(serverKey), 0o600},
		{"server-alt-chain.pem", &p.ServerAltChain, append(encodeCert(alt), encodeCert(inter)...), 0o644},
		{"server-alt.key", &p.ServerAltKey, encodeKey(altKey), 0o600},
		{"server-wildcard-chain.pem", &p.ServerWildcardChain, append(encodeCert(wild), encodeCert(inter)...), 0o644},
		{"server-wildcard.key", &p.ServerWildcardKey, encodeKey(wildKey), 0o600},
		{"client-ca.pem", &p.ClientCACert, encodeCert(clientCA), 0o644},
		{"client-ca.key", &p.ClientCAKey, encodeKey(clientCAKey), 0o600},
		{"client-ok.pem", &p.ClientOKCert, encodeCert(ok), 0o644},
		{"client-ok.key", &p.ClientOKKey, encodeKey(okKey), 0o600},
		{"client-ip.pem", &p.ClientIPCert, encodeCert(ip), 0o644},
		{"client-ip.key", &p.ClientIPKey, encodeKey(ipKey), 0o600},
		{"client-unauth.pem", &p.ClientUnauthCert, encodeCert(unauth), 0o644},
		{"client-unauth.key", &p.ClientUnauthKey, encodeKey(unauthKey), 0o600},
		{"client-expired.pem", &p.ClientExpiredCert, encodeCert(expired), 0o644},
		{"client-expired.key", &p.ClientExpiredKey, encodeKey(expiredKey), 0o600},
		{"client-future.pem", &p.ClientFutureCert, encodeCert(future), 0o644},
		{"client-future.key", &p.ClientFutureKey, encodeKey(futureKey), 0o600},
		{"client-revoked.pem", &p.ClientRevokedCert, encodeCert(revoked), 0o644},
		{"client-revoked.key", &p.ClientRevokedKey, encodeKey(revokedKey), 0o600},
		{"client-wrong-eku.pem", &p.ClientWrongEKUCert, encodeCert(wrong), 0o644},
		{"client-wrong-eku.key", &p.ClientWrongEKUKey, encodeKey(wrongKey), 0o600},
		{"client-unknown.pem", &p.ClientUnknownCert, encodeCert(unknown), 0o644},
		{"client-unknown.key", &p.ClientUnknownKey, encodeKey(unknownKey), 0o600},
		{"client-crl.pem", &p.CRLEmpty, emptyCRL, 0o644},
		{"client-crl-revoked.pem", &p.CRLRevoked, revCRL, 0o644},
	}
	for _, w := range writes {
		path := filepath.Join(dir, w.rel)
		if err := os.WriteFile(path, w.pem, w.mode); err != nil {
			return nil, err
		}
		*w.dest = path
	}
	return p, nil
}

type leafReq struct {
	cn    string
	dns   []string
	ips   []net.IP
	eku   []x509.ExtKeyUsage
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	now   time.Time
	until time.Time
}

func makeCA(cn string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TacLab"}},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func makeIntermediate(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TacLab"}},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func makeLeaf(req leafReq) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.cn, Organization: []string{"TacLab"}},
		NotBefore:    req.now.Add(-time.Minute),
		NotAfter:     req.until,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  req.eku,
		DNSNames:     req.dns,
		IPAddresses:  req.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, req.ca, &key.PublicKey, req.caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func makeCRL(ca *x509.Certificate, caKey *ecdsa.PrivateKey, revoked []*x509.Certificate, now time.Time) ([]byte, error) {
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(365 * 24 * time.Hour),
	}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   c.SerialNumber,
			RevocationTime: now.Add(-time.Hour),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

func encodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func encodeKey(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

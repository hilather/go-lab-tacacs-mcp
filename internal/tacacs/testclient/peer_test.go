package testclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Independent peer PKI. Not the production tls.GenerateLabPKI tree.
type peerPKI struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	roots *x509.CertPool
	now   time.Time
}

func newPeerPKI(t testing.TB) *peerPKI {
	t.Helper()
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "testclient-peer-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &peerPKI{ca: ca, caKey: key, roots: roots, now: now}
}

type leafOpt struct {
	dns  []string
	ips  []net.IP
	uris []string
	srv  string
	cn   string
}

func (p *peerPKI) leaf(t testing.TB, o leafOpt) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	cn := o.cn
	if cn == "" {
		cn = "peer"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    p.now.Add(-time.Minute),
		NotAfter:     p.now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     o.dns,
		IPAddresses:  o.ips,
	}
	for _, raw := range o.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	if o.srv != "" {
		san, err := marshalSRVNameSAN(o.srv)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    oidSubjectAltName,
			Value: san,
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	crt, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	crt.Leaf = leaf
	return crt
}

func marshalSRVNameSAN(name string) ([]byte, error) {
	ia5, err := asn1.MarshalWithParams(name, "ia5")
	if err != nil {
		return nil, err
	}
	type otherName struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue
	}
	onDER, err := asn1.Marshal(otherName{
		TypeID: oidONSRV,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      ia5,
		},
	})
	if err != nil {
		return nil, err
	}
	var on asn1.RawValue
	if _, err := asn1.Unmarshal(onDER, &on); err != nil {
		return nil, err
	}
	gn, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      on.Bytes,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      gn,
	})
}

type byteSink struct {
	mu  sync.Mutex
	buf []byte
}

func (s *byteSink) append(p []byte) {
	s.mu.Lock()
	s.buf = append(s.buf, p...)
	s.mu.Unlock()
}

func (s *byteSink) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf...)
}

type readRecorder struct {
	net.Conn
	sink *byteSink
}

func (r *readRecorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.sink.append(p[:n])
	}
	return n, err
}

// startIndependentPeer is a raw TCP listener. tlsCfg nil means plaintext.
// handle runs on the accepted conn (TLS after handshake when tlsCfg != nil).
// seen captures client→server bytes, including the ClientHello.
func startIndependentPeer(t testing.TB, tlsCfg *tls.Config, handle func(net.Conn)) (addr string, seen *byteSink) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen = &byteSink{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		rec := &readRecorder{Conn: c, sink: seen}
		if tlsCfg == nil {
			if handle != nil {
				handle(rec)
			}
			_ = rec.Close()
			return
		}
		tc := tls.Server(rec, tlsCfg)
		if err := tc.Handshake(); err != nil {
			_ = tc.Close()
			return
		}
		if handle != nil {
			handle(tc)
		}
		_ = tc.Close()
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return ln.Addr().String(), seen
}

func tls13Server(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

func dnsOpts(p *peerPKI, serverName string) TLSOptions {
	return TLSOptions{
		ServerName: serverName,
		Kind:       IdentityDNS,
		Identity:   serverName,
		RootCAs:    p.roots,
		Timeout:    2 * time.Second,
	}
}

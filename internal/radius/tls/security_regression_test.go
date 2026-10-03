package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tctls "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/tls"
)

type challengeBindingProbe struct{ results chan string }

func (p challengeBindingProbe) Handle(ctx context.Context, in server.Request) server.Result {
	store := radiusruntime.NewChallengeStore(1, 1024, time.Minute, nil)
	p.results <- server.IssueChallenge(store, in, radiusruntime.ChallengeIssue{State: []byte("radsec-challenge")})
	return server.Stub{}.Handle(ctx, in)
}

func TestRadSecPropagatesCertificateChallengeBinding(t *testing.T) {
	results := make(chan string, 1)
	ln, _ := startRadSecHandler(t, challengeBindingProbe{results})
	c, err := tctls.Dial(ln.Addr().String(), clientTLS(t, ln.pki))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wire, err := testclient.EncodeAccessRequest([]byte(labSecret), testclient.AccessRequest{Identifier: 1, UserName: "lab-admin", Password: []byte(accessTestPassword), IncludeMA: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	if reason := <-results; reason != "" {
		t.Fatalf("certificate-bound Challenge failed: %s", reason)
	}
}

func TestRadSecCRLAuthenticityAndFreshness(t *testing.T) {
	now := time.Now()
	ca, key := mustCA(t, "client issuer", now)
	leaf, _ := mustLeaf(t, leafReq{ca: ca, caKey: key, now: now})
	other, otherKey := mustCA(t, "unrelated issuer", now)
	cases := []struct {
		name       string
		issuer     *x509.Certificate
		invalid    bool
		this, next time.Time
	}{
		{"valid", ca, false, now.Add(-time.Hour), now.Add(time.Hour)},
		{"expired", ca, true, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", ca, true, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"unrelated", other, true, now.Add(-time.Hour), now.Add(time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := key
			if tc.issuer == other {
				signer = otherKey
			}
			der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: tc.this, NextUpdate: tc.next}, tc.issuer, signer)
			if err != nil {
				t.Fatal(err)
			}
			crl, err := x509.ParseRevocationList(der)
			if err != nil {
				t.Fatal(err)
			}
			err = revokedBy([]*x509.RevocationList{crl}, leaf, []*x509.Certificate{ca}, now)
			if (err != nil) != tc.invalid {
				t.Fatalf("invalid=%v err=%v", tc.invalid, err)
			}
		})
	}
}

func BenchmarkRadSecCRLValidation(b *testing.B) {
	now := time.Now()
	ca, key := mustCA(b, "client issuer", now)
	leaf, _ := mustLeaf(b, leafReq{ca: ca, caKey: key, now: now})
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, ca, key)
	if err != nil {
		b.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		b.Fatal(err)
	}
	lists, issuers := []*x509.RevocationList{crl}, []*x509.Certificate{ca}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := revokedBy(lists, leaf, issuers, now); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRadSecCRLSignatureAndIssuerIsolation(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	ca, key := mustCA(t, "issuer", now)
	leaf, _ := mustLeaf(t, leafReq{ca: ca, caKey: key, now: now})
	other, otherKey := mustCA(t, "other", now)
	makeList := func(issuer *x509.Certificate, signer *ecdsa.PrivateKey, revoked bool) *x509.RevocationList {
		tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}
		if revoked {
			tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute)}}
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, signer)
		if err != nil {
			t.Fatal(err)
		}
		list, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		return list
	}
	valid := makeList(ca, key, false)
	unrelated := makeList(other, otherKey, true)
	if err := revokedBy([]*x509.RevocationList{unrelated, valid}, leaf, []*x509.Certificate{ca}, now); err != nil {
		t.Fatalf("unrelated same-serial CRL affected client: %v", err)
	}
	valid.Signature[0] ^= 1
	if err := revokedBy([]*x509.RevocationList{valid}, leaf, []*x509.Certificate{ca}, now); err == nil {
		t.Fatal("bad signature admitted client")
	}
	if err := revokedBy([]*x509.RevocationList{makeList(ca, key, true)}, leaf, []*x509.Certificate{ca}, now); err == nil {
		t.Fatal("signed revocation admitted client")
	}
}

func TestRadSecCRLUsesVerifiedRootOmittedByPeer(t *testing.T) {
	pki := generateLabPKI(t, t.TempDir())
	readCert := func(path string) *x509.Certificate {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	leaf, root := readCert(pki.ClientCert), readCert(pki.ClientCA)
	l := &Listener{crlPath: pki.CRL, opts: Options{Now: time.Now}}
	if err := l.verifyPeer(cryptotls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, root}}}); err != nil {
		t.Fatalf("verified root missing from peer chain: %v", err)
	}
}

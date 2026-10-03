package tls

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"math/big"
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
			err = revokedBy([]*x509.RevocationList{crl}, leaf, []*x509.Certificate{ca})
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
		if err := revokedBy(lists, leaf, issuers); err != nil {
			b.Fatal(err)
		}
	}
}

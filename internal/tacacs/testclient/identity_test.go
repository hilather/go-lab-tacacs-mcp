package testclient

import (
	"crypto/x509"
	"errors"
	"net"
	"testing"
)

// T98-ROLE-003: certificate-name matrix. URI-ID is never a match source.
func TestServerIdentityMatrix(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)

	dns := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}, cn: "cn.lab.example"})
	ip := p.leaf(t, leafOpt{ips: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}})
	wild := p.leaf(t, leafOpt{dns: []string{"*.tacacs.lab.example"}})
	srv := p.leaf(t, leafOpt{srv: "_tacacss.lab.example"})
	uriOnly := p.leaf(t, leafOpt{uris: []string{"tacacs://tacacs.lab.example"}, cn: "tacacs.lab.example"})
	dnsAndURI := p.leaf(t, leafOpt{
		dns:  []string{"other.tacacs.lab.example"},
		uris: []string{"tacacs://tacacs.lab.example"},
	})

	cases := []struct {
		name string
		cert *x509.Certificate
		kind IdentityKind
		ref  string
		err  error
	}{
		{"dns match", dns.Leaf, IdentityDNS, "tacacs.lab.example", nil},
		{"dns case", dns.Leaf, IdentityDNS, "TACACS.LAB.EXAMPLE", nil},
		{"dns miss", dns.Leaf, IdentityDNS, "other.lab.example", ErrIdentityMismatch},
		{"dns ignores cn", dns.Leaf, IdentityDNS, "cn.lab.example", ErrIdentityMismatch},
		{"wildcard match", wild.Leaf, IdentityDNS, "r1.tacacs.lab.example", nil},
		{"wildcard not apex", wild.Leaf, IdentityDNS, "tacacs.lab.example", ErrIdentityMismatch},
		{"wildcard not multi", wild.Leaf, IdentityDNS, "a.b.tacacs.lab.example", ErrIdentityMismatch},
		{"ip v4", ip.Leaf, IdentityIP, "127.0.0.1", nil},
		{"ip v6", ip.Leaf, IdentityIP, "::1", nil},
		{"ip miss", ip.Leaf, IdentityIP, "192.0.2.1", ErrIdentityMismatch},
		{"ip literal promotes", ip.Leaf, IdentityDNS, "127.0.0.1", nil},
		{"srv match", srv.Leaf, IdentitySRV, "_tacacss.lab.example", nil},
		{"srv case", srv.Leaf, IdentitySRV, "_TACACSS.LAB.EXAMPLE", nil},
		{"srv miss", srv.Leaf, IdentitySRV, "_tacacss.other.example", ErrIdentityMismatch},
		{"srv not dns", srv.Leaf, IdentityDNS, "lab.example", ErrIdentityMismatch},
		{"uri-id rejected", uriOnly.Leaf, IdentityURI, "tacacs://tacacs.lab.example", ErrURIIDNotUsed},
		{"uri-only not dns", uriOnly.Leaf, IdentityDNS, "tacacs.lab.example", ErrIdentityMismatch},
		{"uri-only not via cn", uriOnly.Leaf, IdentityDNS, "tacacs.lab.example", ErrIdentityMismatch},
		{"dns+uri uses dns only", dnsAndURI.Leaf, IdentityDNS, "other.tacacs.lab.example", nil},
		{"dns+uri ignores uri host", dnsAndURI.Leaf, IdentityDNS, "tacacs.lab.example", ErrIdentityMismatch},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyServerIdentity(tc.cert, tc.kind, tc.ref)
			if tc.err == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("err=%v, want %v", err, tc.err)
			}
		})
	}

	if got := SRVNames(srv.Leaf); len(got) != 1 || got[0] != "_tacacss.lab.example" {
		t.Fatalf("SRVNames=%v", got)
	}
	if n := len(uriOnly.Leaf.URIs); n != 1 {
		t.Fatalf("uri-only cert should have URI SAN, got %d (matrix must see it and ignore it)", n)
	}
}

func TestDialTLSURIKindRejected(t *testing.T) {
	t.Parallel()
	_, err := DialTLS("127.0.0.1:1", TLSOptions{Kind: IdentityURI, RootCAs: x509.NewCertPool()})
	if !errors.Is(err, ErrURIIDNotUsed) {
		t.Fatalf("err=%v", err)
	}
}

func TestDialTLSIdentityKindsOverWire(t *testing.T) {
	t.Parallel()
	p := newPeerPKI(t)

	t.Run("dns", func(t *testing.T) {
		t.Parallel()
		cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		c, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("ip", func(t *testing.T) {
		t.Parallel()
		cert := p.leaf(t, leafOpt{ips: []net.IP{net.ParseIP("127.0.0.1")}})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		c, err := DialTLS(addr, TLSOptions{Kind: IdentityIP, Identity: "127.0.0.1", RootCAs: p.roots})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("srv", func(t *testing.T) {
		t.Parallel()
		cert := p.leaf(t, leafOpt{srv: "_tacacss.lab.example"})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		c, err := DialTLS(addr, TLSOptions{
			Kind:     IdentitySRV,
			Identity: "_tacacss.lab.example",
			RootCAs:  p.roots,
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("wrong dns", func(t *testing.T) {
		t.Parallel()
		cert := p.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		_, err := DialTLS(addr, dnsOpts(p, "other.lab.example"))
		if err == nil {
			t.Fatal("expected identity failure")
		}
	})
	t.Run("uri only rejected", func(t *testing.T) {
		t.Parallel()
		cert := p.leaf(t, leafOpt{uris: []string{"tacacs://tacacs.lab.example"}})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		_, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
		if err == nil {
			t.Fatal("URI-ID must not authenticate the server")
		}
	})
	t.Run("unknown CA", func(t *testing.T) {
		t.Parallel()
		other := newPeerPKI(t)
		cert := other.leaf(t, leafOpt{dns: []string{"tacacs.lab.example"}})
		addr, _ := startIndependentPeer(t, tls13Server(cert), func(c net.Conn) {
			_, _ = c.Read(make([]byte, 1))
		})
		_, err := DialTLS(addr, dnsOpts(p, "tacacs.lab.example"))
		if err == nil {
			t.Fatal("unknown server CA must fail")
		}
	})
}

package testclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// TLSOptions configures RFC 9887 client-role dial.
//
// There is no 0-RTT / early_data path: ClientSessionCache is not set and
// crypto/tls is never asked to send early application data.
type TLSOptions struct {
	// ServerName is the SNI server_name (RFC 9887 §3.4.2). Distinct from
	// the TCP host. When empty and Kind is DNS, Identity is used.
	ServerName string
	// Kind is the RFC 9525 identifier type. URI-ID is rejected.
	Kind IdentityKind
	// Identity is the reference identifier (DNS name, IP, or _service.name).
	// Empty uses ServerName, then the TCP host.
	Identity string
	// Certificates are presented for mTLS when the peer requests them.
	Certificates []tls.Certificate
	// RootCAs trusts the server path. Required.
	RootCAs *x509.CertPool
	// Timeout bounds TCP dial + handshake. Default 2s.
	Timeout time.Duration
	// Dial overrides TCP dial (tests: wrap/record). Must not implement fallback.
	Dial func(network, address string) (net.Conn, error)
}

// DialTLS opens TCP to addr and begins TLS 1.3 immediately. No TACACS
// bytes are written before Handshake returns. A TLS failure is terminal:
// this function never falls back to Dial (legacy).
func DialTLS(addr string, opts TLSOptions) (*Conn, error) {
	if opts.Kind == IdentityURI {
		return nil, ErrURIIDNotUsed
	}
	if opts.RootCAs == nil {
		return nil, fmt.Errorf("tls root CAs are required")
	}
	kind, ref := resolveIdentity(addr, opts)
	if kind == IdentityURI {
		return nil, ErrURIIDNotUsed
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.Dial
	}
	raw, err := dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	sni := opts.ServerName
	if sni == "" && kind == IdentityDNS {
		sni = ref
	}
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	cfg := clientTLSConfig(opts, sni, kind, ref)
	_ = raw.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return NewTLS(tc), nil
}

func clientTLSConfig(opts TLSOptions, sni string, kind IdentityKind, ref string) *tls.Config {
	roots := opts.RootCAs
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         sni,
		RootCAs:            roots,
		Certificates:       opts.Certificates,
		InsecureSkipVerify: true, // identity + path checked in VerifyConnection
		// ClientSessionCache left nil: no tickets, no 0-RTT, no early_data.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyTLSPeer(cs, roots, kind, ref)
		},
	}
}

func verifyTLSPeer(cs tls.ConnectionState, roots *x509.CertPool, kind IdentityKind, ref string) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrNoServerCertificate
	}
	leaf := cs.PeerCertificates[0]
	vopts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, c := range cs.PeerCertificates[1:] {
		if c != nil {
			vopts.Intermediates.AddCert(c)
		}
	}
	if _, err := leaf.Verify(vopts); err != nil {
		return err
	}
	return VerifyServerIdentity(leaf, kind, ref)
}

func resolveIdentity(addr string, opts TLSOptions) (IdentityKind, string) {
	ref := opts.Identity
	if ref == "" {
		ref = opts.ServerName
	}
	if ref == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ref = host
	}
	kind := opts.Kind
	if kind == IdentityDNS && net.ParseIP(ref) != nil {
		kind = IdentityIP
	}
	return kind, ref
}

// NewTLS wraps a connection that has already completed a TLS handshake
// and enables RFC 9887 packet rules (UNENCRYPTED required; no obfuscation).
func NewTLS(nc net.Conn) *Conn {
	return &Conn{nc: nc, tls: true}
}

// OverTLS reports whether this conn applies TLS client-role packet rules.
func (c *Conn) OverTLS() bool {
	return c != nil && c.tls
}

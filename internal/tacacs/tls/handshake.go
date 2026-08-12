package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

// extensionEarlyData is TLS 1.3 early_data (RFC 8446 §4.2.10).
const extensionEarlyData uint16 = 42

type tlsProfile struct {
	id          string
	serverNames []string
	chainFile   string
	keyRef      config.SecretRef
}

func (l *Listener) buildTLS() (*tls.Config, error) {
	settings := l.opts.Settings.TLS
	if settings.MinimumVersion != "" && settings.MinimumVersion != "TLS1.3" {
		return nil, domain.NewError(domain.CodeTLSVersionUnsupported, "secure TACACS minimum_version must be TLS1.3")
	}
	if settings.ClientAuthentication != "" && settings.ClientAuthentication != "require_and_verify_certificate" {
		return nil, errors.New("client_authentication must be require_and_verify_certificate")
	}
	if !settings.RejectEarlyData {
		return nil, errors.New("reject_early_data cannot be disabled")
	}

	clientCAs, err := loadCertPool(settings.ClientCABundle.File)
	if err != nil {
		return nil, fmt.Errorf("client CA bundle: %w", err)
	}
	if settings.Revocation.Mode == "configured_crl" {
		if _, err := loadCRLs(settings.Revocation.CRLBundle.File); err != nil {
			return nil, fmt.Errorf("crl bundle: %w", err)
		}
	}

	profiles := make([]tlsProfile, 0, len(settings.Identities.Profiles))
	byID := make(map[string]tlsProfile, len(settings.Identities.Profiles))
	for _, p := range settings.Identities.Profiles {
		tp := tlsProfile{
			id:          p.ID,
			serverNames: append([]string(nil), p.ServerNames...),
			chainFile:   p.CertificateChain.File,
			keyRef:      p.PrivateKey,
		}
		if _, err := l.loadProfile(tp); err != nil {
			return nil, fmt.Errorf("tls identity %s: %w", p.ID, err)
		}
		profiles = append(profiles, tp)
		byID[p.ID] = tp
	}
	if len(profiles) == 0 {
		return nil, errors.New("at least one tls identity profile is required")
	}
	defaultID := settings.Identities.DefaultID
	if defaultID == "" {
		defaultID = profiles[0].id
	}
	def, ok := byID[defaultID]
	if !ok {
		return nil, fmt.Errorf("default tls identity %q is not defined", defaultID)
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		// TLS 1.3 suites are selected by crypto/tls (ADR-0004). Do not set CipherSuites.
		// Ticket keys stay on this Config so GetConfigForClient clones share
		// auto-rotated keys (ADR-0005). Do not call SetSessionTicketKeys.
	}
	cfg.GetCertificate = l.getCertificate
	if !settings.SessionResumption.Enabled || settings.SessionResumption.TicketLifetime == 0 {
		cfg.SessionTicketsDisabled = true
	}

	l.profiles = profiles
	l.defaultProfile = def
	l.requireSNI = settings.Identities.RequireSNI
	l.clientCAFile = settings.ClientCABundle.File
	l.clientCAs = clientCAs
	l.clientCACerts = parseCertsFromFile(settings.ClientCABundle.File)
	l.crlPath = settings.Revocation.CRLBundle.File

	cfg.GetConfigForClient = l.configForClient
	return cfg, nil
}

func (l *Listener) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello == nil {
		return nil, errors.New("missing client hello")
	}
	for _, ext := range hello.Extensions {
		if ext == extensionEarlyData {
			return nil, errEarlyData
		}
	}
	cfg := l.tlsCfg.Clone()
	cfg.GetConfigForClient = nil
	if pool, err := loadCertPool(l.clientCAFile); err == nil {
		cfg.ClientCAs = pool
	} else {
		return nil, err
	}
	peer := net.IP(nil)
	if hello.Conn != nil {
		peer = peerIP(hello.Conn.RemoteAddr())
	}
	cfg.GetCertificate = l.getCertificate
	var bound *boundConn
	if hello.Conn != nil {
		if bc, ok := hello.Conn.(*boundConn); ok {
			bound = bc
		}
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		id, err := l.verifyConnection(cs, peer)
		if err != nil {
			return err
		}
		if bound != nil {
			bound.identity = id
		}
		return nil
	}
	return cfg, nil
}

func (l *Listener) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := ""
	if hello != nil {
		name = strings.ToLower(strings.TrimSpace(hello.ServerName))
	}
	if l.requireSNI && name == "" {
		return nil, errNoServerName
	}
	if name != "" {
		for _, p := range l.profiles {
			for _, sn := range p.serverNames {
				if strings.EqualFold(sn, name) || matchWildcard(sn, name) {
					return l.loadProfile(p)
				}
			}
		}
		if l.requireSNI {
			return nil, errUnknownSNI
		}
	}
	return l.loadProfile(l.defaultProfile)
}

func (l *Listener) loadProfile(p tlsProfile) (*tls.Certificate, error) {
	if p.chainFile == "" {
		return nil, errors.New("certificate chain file is required")
	}
	chain, err := os.ReadFile(p.chainFile)
	if err != nil {
		return nil, err
	}
	if l.opts.Secrets == nil {
		return nil, errors.New("secret lookup is required")
	}
	key, err := l.opts.Secrets(p.keyRef)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(chain, key)
	wipe(key)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr == nil {
			cert.Leaf = leaf
			if err := checkServerIdentity(leaf); err != nil {
				return nil, err
			}
			if hasWildcardSAN(leaf) && l.opts.Logger != nil {
				l.opts.Logger.Warn("wildcard server identity in use; restrict to a TACACS-only subdomain", "profile", p.id)
			}
		}
	}
	return &cert, nil
}

func checkServerIdentity(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("server certificate is missing")
	}
	for _, n := range cert.DNSNames {
		if err := config.ValidateWildcardServerName(n); err != nil {
			return err
		}
	}
	return nil
}

func hasWildcardSAN(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, n := range cert.DNSNames {
		if strings.Contains(n, "*") {
			return true
		}
	}
	return false
}

func (l *Listener) verifyConnection(cs tls.ConnectionState, peer net.IP) (server.Identity, error) {
	if len(cs.PeerCertificates) == 0 {
		return server.Identity{}, errNoClientCert
	}
	leaf := cs.PeerCertificates[0]
	roots, caCerts, err := l.loadClientTrust()
	if err != nil {
		return server.Identity{}, err
	}
	chains := cs.VerifiedChains
	if len(chains) == 0 {
		parsed, err := verifyClientPath(leaf, cs.PeerCertificates[1:], roots)
		if err != nil {
			return server.Identity{}, err
		}
		chains = parsed
	}
	issuers := issuersFromChains(chains)
	issuers = append(issuers, caCerts...)
	lists, err := loadCRLs(l.crlPath)
	if err != nil {
		return server.Identity{}, err
	}
	if err := revokedBy(lists, leaf, issuers, time.Now()); err != nil {
		return server.Identity{}, err
	}
	snap := l.opts.Snapshot()
	if snap == nil {
		return server.Identity{}, errors.New("no published snapshot")
	}
	client, err := snap.MatchClient(domain.TransportTLS, peer, certIdentity(leaf))
	if err != nil {
		return server.Identity{}, err
	}
	return server.Identity{
		ClientID:  client.Client.ID,
		Transport: domain.TransportTLS,
		Peer:      append(net.IP(nil), peer...),
		Revision:  snap.Revision,
	}, nil
}

func (l *Listener) loadClientTrust() (*x509.CertPool, []*x509.Certificate, error) {
	pool, err := loadCertPool(l.clientCAFile)
	if err != nil {
		return nil, nil, err
	}
	return pool, parseCertsFromFile(l.clientCAFile), nil
}

func verifyClientPath(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool) ([][]*x509.Certificate, error) {
	if leaf == nil {
		return nil, errNoClientCert
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, c := range intermediates {
		if c != nil {
			opts.Intermediates.AddCert(c)
		}
	}
	return leaf.Verify(opts)
}

func issuersFromChains(chains [][]*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	seen := map[string]struct{}{}
	for _, chain := range chains {
		for i, c := range chain {
			if i == 0 || c == nil {
				continue
			}
			k := string(c.Raw)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("client CA bundle path is required")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("client CA bundle contains no certificates")
	}
	return pool, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseCertsFromFile(path string) []*x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []*x509.Certificate
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

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
		return nil, domain.NewError(domain.CodeTLSVersionUnsupported, "RadSec minimum_version must be TLS1.3")
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
	}
	if !settings.SessionResumption.Enabled || settings.SessionResumption.TicketLifetime == 0 {
		cfg.SessionTicketsDisabled = true
	}
	l.profiles = profiles
	l.defaultProfile = def
	l.requireSNI = settings.Identities.RequireSNI
	l.clientCAFile = settings.ClientCABundle.File
	l.crlPath = settings.Revocation.CRLBundle.File
	cfg.GetCertificate = l.getCertificate
	cfg.GetConfigForClient = l.configForClient
	return cfg, nil
}

func (l *Listener) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello == nil {
		return nil, errors.New("missing client hello")
	}
	for _, ext := range hello.Extensions {
		if ext == extensionEarlyData {
			return nil, errors.New("early data is rejected")
		}
	}
	cfg := l.tlsCfg.Clone()
	cfg.GetConfigForClient = nil
	pool, err := loadCertPool(l.clientCAFile)
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = pool
	cfg.GetCertificate = l.getCertificate
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return l.verifyPeer(cs)
	}
	return cfg, nil
}

func (l *Listener) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := ""
	if hello != nil {
		name = strings.ToLower(strings.TrimSpace(hello.ServerName))
	}
	if l.requireSNI && name == "" {
		return nil, errors.New("server name is required")
	}
	if name != "" {
		for _, p := range l.profiles {
			for _, sn := range p.serverNames {
				if strings.EqualFold(sn, name) {
					return l.loadProfile(p)
				}
			}
		}
		if l.requireSNI {
			return nil, errors.New("unknown server name")
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
		}
	}
	return &cert, nil
}

func (l *Listener) verifyPeer(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("client certificate is required")
	}
	if l.crlPath != "" {
		lists, err := loadCRLs(l.crlPath)
		if err != nil {
			return err
		}
		leaf := cs.PeerCertificates[0]
		issuers := cs.PeerCertificates[1:]
		if err := revokedBy(lists, leaf, issuers); err != nil {
			return err
		}
	}
	return nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("client CA bundle path is required")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("client CA bundle contains no certificates")
	}
	return pool, nil
}

func loadCRLs(path string) ([]*x509.RevocationList, error) {
	if path == "" {
		return nil, errors.New("crl bundle path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lists []*x509.RevocationList
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		lists = append(lists, crl)
	}
	if len(lists) == 0 {
		return nil, errors.New("crl bundle contains no CRLs")
	}
	return lists, nil
}

func revokedBy(lists []*x509.RevocationList, cert *x509.Certificate, issuers []*x509.Certificate) error {
	if cert == nil {
		return errors.New("client certificate is required")
	}
	for _, crl := range lists {
		if crl == nil {
			continue
		}
		for _, rc := range crl.RevokedCertificateEntries {
			if rc.SerialNumber != nil && cert.SerialNumber != nil && rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errors.New("client certificate is revoked")
			}
		}
		_ = issuers
	}
	return nil
}

func certIdentity(cert *x509.Certificate) *config.CertIdentity {
	if cert == nil {
		return nil
	}
	dns := make([]string, 0, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		n = strings.TrimSpace(n)
		if n != "" {
			dns = append(dns, n)
		}
	}
	ips := make([]net.IP, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		if ip != nil {
			ips = append(ips, append(net.IP(nil), ip...))
		}
	}
	return &config.CertIdentity{DNSSANs: dns, IPSANs: ips}
}

func certFingerprint(cert *x509.Certificate) [32]byte {
	if cert == nil {
		return [32]byte{}
	}
	return sha256.Sum256(cert.Raw)
}

func peerIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if a, ok := addr.(*net.TCPAddr); ok {
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return net.ParseIP(addr.String())
	}
	return net.ParseIP(host)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

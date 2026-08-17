package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/eap/peap"
	radiusserver "github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

// attachPEAP binds a server-authenticated TLS 1.3 PEAP endpoint when a
// configured RadSec or SecureTACACS identity exists. It never mints a
// certificate. Missing identity leaves PEAP unset so Identity+peap fail-closes.
func attachPEAP(access radiusserver.Access, doc *config.Document, lookup config.SecretLookup) (radiusserver.Access, error) {
	cert, ok, err := loadPEAPCertificate(doc, lookup)
	if err != nil {
		return access, err
	}
	if !ok {
		return access, nil
	}
	srv, err := peap.NewServer(cert)
	if err != nil {
		return access, fmt.Errorf("peap server: %w", err)
	}
	access.PEAP = srv
	access.Tunnels = peap.NewRegistry()
	return access, nil
}

// loadPEAPCertificate reuses the default RadSec TLS identity, then the
// SecureTACACS default. Disabled listeners still count: operators attach the
// existing lab PKI without opening 2083 or 300. No second PEAP YAML key.
func loadPEAPCertificate(doc *config.Document, lookup config.SecretLookup) (tls.Certificate, bool, error) {
	if doc == nil {
		return tls.Certificate{}, false, nil
	}
	if p, ok := peapTLSProfile(doc.Listeners.RADIUSRadSec.TLS); ok {
		cert, err := loadTLSProfileCert(p, lookup)
		if err != nil {
			return tls.Certificate{}, false, fmt.Errorf("radsec tls identity %s: %w", p.ID, err)
		}
		return cert, true, nil
	}
	if p, ok := peapTLSProfile(doc.Listeners.SecureTACACS.TLS); ok {
		cert, err := loadTLSProfileCert(p, lookup)
		if err != nil {
			return tls.Certificate{}, false, fmt.Errorf("secure_tacacs tls identity %s: %w", p.ID, err)
		}
		return cert, true, nil
	}
	return tls.Certificate{}, false, nil
}

func peapTLSProfile(tlsCfg config.SecureTLS) (config.TLSProfile, bool) {
	id := tlsCfg.Identities.DefaultID
	if id != "" {
		for _, p := range tlsCfg.Identities.Profiles {
			if p.ID == id && usablePEAPProfile(p) {
				return p, true
			}
		}
	}
	for _, p := range tlsCfg.Identities.Profiles {
		if usablePEAPProfile(p) {
			return p, true
		}
	}
	return config.TLSProfile{}, false
}

func usablePEAPProfile(p config.TLSProfile) bool {
	return p.CertificateChain.File != "" && p.PrivateKey.Set()
}

func loadTLSProfileCert(p config.TLSProfile, lookup config.SecretLookup) (tls.Certificate, error) {
	chain, err := os.ReadFile(p.CertificateChain.File)
	if err != nil {
		return tls.Certificate{}, err
	}
	if lookup == nil {
		return tls.Certificate{}, fmt.Errorf("secret lookup is required")
	}
	key, err := lookup(p.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(chain, key)
	crypto.Wipe(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) > 0 {
		if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
			cert.Leaf = leaf
		}
	}
	return cert, nil
}

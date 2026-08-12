package tls

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"
)

func loadCRLs(path string) ([]*x509.RevocationList, error) {
	if path == "" {
		return nil, errCRLUnreadable
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errCRLUnreadable
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
			return nil, errCRLUnverifiable
		}
		lists = append(lists, crl)
	}
	if len(lists) == 0 {
		// An empty but present bundle is a valid "nothing revoked" set
		// only when it contains at least one parseable CRL. Fail closed
		// on a zero-CRL file so a truncated bundle cannot disable checks.
		return nil, errCRLUnverifiable
	}
	return lists, nil
}

func revokedBy(lists []*x509.RevocationList, cert *x509.Certificate, issuers []*x509.Certificate, now time.Time) error {
	if cert == nil {
		return errNoClientCert
	}
	checked := false
	for _, crl := range lists {
		if crl == nil {
			continue
		}
		issuer := issuerForCRL(crl, issuers)
		if issuer == nil {
			continue
		}
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return errCRLUnverifiable
		}
		if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
			return errCRLUnverifiable
		}
		checked = true
		for _, rc := range crl.RevokedCertificateEntries {
			if rc.SerialNumber != nil && cert.SerialNumber != nil && rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errRevoked
			}
		}
	}
	if !checked {
		return errCRLUnverifiable
	}
	return nil
}

func issuerForCRL(crl *x509.RevocationList, issuers []*x509.Certificate) *x509.Certificate {
	for _, iss := range issuers {
		if iss == nil {
			continue
		}
		if crl.CheckSignatureFrom(iss) == nil {
			return iss
		}
	}
	return nil
}

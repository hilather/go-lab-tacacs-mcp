package testclient

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// IdentityKind selects the RFC 9525 identifier type for server identity.
// RFC 9887 §3.4.2 allows DNS-ID, IP-ID, and SRV-ID only.
type IdentityKind int

const (
	// IdentityDNS is DNS-ID (dNSName SAN). Zero value; IP literals are
	// promoted to IdentityIP when resolving a reference identity.
	IdentityDNS IdentityKind = iota
	// IdentityIP is IP-ID (iPAddress SAN).
	IdentityIP
	// IdentitySRV is SRV-ID (otherName SRVName, RFC 4985).
	IdentitySRV
	// IdentityURI is rejected. It exists so tests can prove URI-ID is unused.
	IdentityURI
)

func (k IdentityKind) String() string {
	switch k {
	case IdentityDNS:
		return "dns-id"
	case IdentityIP:
		return "ip-id"
	case IdentitySRV:
		return "srv-id"
	case IdentityURI:
		return "uri-id"
	default:
		return fmt.Sprintf("identity-kind(%d)", int(k))
	}
}

// oidSubjectAltName is id-ce-subjectAltName (2.5.29.17).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// oidONSRV is id-on-dnsSRV (1.3.6.1.5.5.7.8.7) from RFC 4985.
var oidONSRV = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7}

// VerifyServerIdentity matches cert against a single RFC 9525 identifier
// type. URI SANs and the subject CN are never consulted.
func VerifyServerIdentity(cert *x509.Certificate, kind IdentityKind, ref string) error {
	if cert == nil {
		return ErrNoServerCertificate
	}
	ref = normalizeID(ref)
	if ref == "" {
		return fmt.Errorf("%w: empty reference identity", ErrIdentityMismatch)
	}
	if kind == IdentityURI {
		return ErrURIIDNotUsed
	}
	// IP literals must use IP-ID even if the caller left Kind at DNS.
	if kind == IdentityDNS && net.ParseIP(ref) != nil {
		kind = IdentityIP
	}
	ok := false
	switch kind {
	case IdentityDNS:
		ok = matchDNSID(cert, ref)
	case IdentityIP:
		ok = matchIPID(cert, ref)
	case IdentitySRV:
		ok = matchSRVID(cert, ref)
	default:
		return fmt.Errorf("unsupported server identity kind %s", kind)
	}
	if !ok {
		return fmt.Errorf("%w: %s %q", ErrIdentityMismatch, kind, ref)
	}
	return nil
}

func normalizeID(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func matchDNSID(cert *x509.Certificate, ref string) bool {
	for _, n := range cert.DNSNames {
		n = normalizeID(n)
		if n == "" {
			continue
		}
		if n == ref || matchLeftmostDNSWildcard(n, ref) {
			return true
		}
	}
	return false
}

// matchLeftmostDNSWildcard implements RFC 9525 leftmost-label `*`.
func matchLeftmostDNSWildcard(pattern, name string) bool {
	if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	rest := strings.TrimSuffix(name, suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

func matchIPID(cert *x509.Certificate, ref string) bool {
	ip := net.ParseIP(ref)
	if ip == nil {
		return false
	}
	for _, cand := range cert.IPAddresses {
		if cand != nil && cand.Equal(ip) {
			return true
		}
	}
	return false
}

func matchSRVID(cert *x509.Certificate, ref string) bool {
	if !strings.HasPrefix(ref, "_") || !strings.Contains(ref, ".") {
		return false
	}
	for _, n := range SRVNames(cert) {
		if normalizeID(n) == ref {
			return true
		}
	}
	return false
}

// SRVNames returns RFC 4985 SRVName otherName values from the SAN.
func SRVNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return parseSRVNames(ext.Value)
		}
	}
	return nil
}

func parseSRVNames(der []byte) []string {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil
	}
	_ = rest
	inner := seq.Bytes
	var out []string
	for len(inner) > 0 {
		var gn asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &gn)
		if err != nil {
			break
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue
		}
		// OtherName: OID + [0] EXPLICIT ANY
		var oid asn1.ObjectIdentifier
		payload, err := asn1.Unmarshal(gn.Bytes, &oid)
		if err != nil || !oid.Equal(oidONSRV) {
			continue
		}
		var expl asn1.RawValue
		if _, err := asn1.Unmarshal(payload, &expl); err != nil {
			continue
		}
		if expl.Class != asn1.ClassContextSpecific || expl.Tag != 0 {
			continue
		}
		var s string
		if _, err := asn1.UnmarshalWithParams(expl.Bytes, &s, "ia5"); err == nil && s != "" {
			out = append(out, s)
		}
	}
	return out
}

package tls

import (
	"crypto/x509"
	"net"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

// certIdentity extracts dNSName and iPAddress SANs for client matching.
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

func peerIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	default:
		if addr == nil {
			return nil
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

func matchWildcard(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	name = strings.ToLower(strings.TrimSpace(name))
	if pattern == "" || name == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == name
	}
	if config.ValidateWildcardServerName(pattern) != nil {
		return false
	}
	suffix := pattern[1:] // ".tacacs.…"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	rest := strings.TrimSuffix(name, suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

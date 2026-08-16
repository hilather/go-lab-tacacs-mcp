package config

import (
	"net"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func tlsRADIUSClientsYAML() []byte {
	return []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: radsec
    priority: 10
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access, accounting]
        radius:
          shared_secret: {file: /run/secrets/tls}
  - id: udp-only
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/udp}
`)
}

func TestCompileRADIUSIndexIsPerCarrier(t *testing.T) {
	t.Parallel()
	doc, err := Parse(tlsRADIUSClientsYAML())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
	udp, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	id, epid, err := udp.Match(net.ParseIP("192.0.2.10"))
	if err != nil || id != "udp-only" || epid != "radius-udp" {
		t.Fatalf("udp match=%s ep=%s err=%v", id, epid, err)
	}
	if _, _, err := udp.Match(net.ParseIP("198.51.100.1")); err == nil {
		t.Fatal("TLS-only client must not appear in the UDP index")
	}
	if _, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSTLS); err == nil {
		t.Fatal("TLS carrier must use CompileRADIUSCertIndex")
	}
}

func TestCompileRADIUSCertIndexCertificateOnly(t *testing.T) {
	t.Parallel()
	doc, err := Parse(tlsRADIUSClientsYAML())
	if err != nil {
		t.Fatal(err)
	}
	idx, err := CompileRADIUSCertIndex(doc.Clients, domain.RoleAccess)
	if err != nil {
		t.Fatal(err)
	}
	id, epid, err := idx.Match(net.ParseIP("198.51.100.1"), &CertIdentity{DNSSANs: []string{"nas.lab.example"}})
	if err != nil || id != "radsec" || epid != "radius-tls" {
		t.Fatalf("cert match=%s ep=%s err=%v", id, epid, err)
	}
	_, _, err = idx.Match(net.ParseIP("192.0.2.10"), &CertIdentity{DNSSANs: []string{"other.lab.example"}})
	if err == nil {
		t.Fatal("unknown cert must miss")
	}
}

func TestRADIUSCertIndexAddressAndCertificateRequiresCIDRs(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: radsec
    match:
      mode: address_and_certificate
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/tls}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateV2(doc)
	if err == nil || !strings.Contains(err.Error(), "source_cidrs") {
		t.Fatalf("got %v", err)
	}
}

func TestRADIUSCertIndexAddressAndCertificateMatch(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: radsec
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/tls}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
	idx, err := CompileRADIUSCertIndex(doc.Clients, domain.RoleAccess)
	if err != nil {
		t.Fatal(err)
	}
	cert := &CertIdentity{DNSSANs: []string{"nas.lab.example"}}
	id, _, err := idx.Match(net.ParseIP("192.0.2.10"), cert)
	if err != nil || id != "radsec" {
		t.Fatalf("match=%s err=%v", id, err)
	}
	if _, _, err := idx.Match(net.ParseIP("198.51.100.1"), cert); err == nil {
		t.Fatal("peer IP outside CIDR must miss in address_and_certificate")
	}
}

func TestRADIUSCertIndexAmbiguousTie(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: zebra
    priority: 10
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: a
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
  - id: alpha
    priority: 10
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: b
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateV2(doc)
	if err == nil {
		t.Fatal("expected ambiguous compile")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
}

package config

import (
	"net"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestRADIUSIndexRoleSeparation(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: access-only
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: rad-access
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
  - id: acct-only
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: rad-acct
        protocol: radius
        transport: udp
        roles: [accounting]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatalf("same CIDR different roles must compile: %v", err)
	}
	acc, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccounting, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	got, epid, err := acc.Match(net.ParseIP("192.0.2.10"))
	if err != nil || got != "access-only" || epid != "rad-access" {
		t.Fatalf("access=%q ep=%q err=%v", got, epid, err)
	}
	got, epid, err = acct.Match(net.ParseIP("192.0.2.10"))
	if err != nil || got != "acct-only" || epid != "rad-acct" {
		t.Fatalf("acct=%q ep=%q err=%v", got, epid, err)
	}
}

func TestRADIUSIndexAmbiguousSameRole(t *testing.T) {
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
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r1
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
  - id: alpha
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r2
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err == nil {
		t.Fatal("expected CLIENT_MATCH_AMBIGUOUS")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Message, "alpha") || !strings.Contains(de.Message, "zebra") {
		t.Fatalf("error should name both ids: %v", err)
	}
	_, err = CompileRADIUSIndex(doc.Clients, domain.RoleAccounting, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatalf("accounting index is empty, not ambiguous: %v", err)
	}
}

func TestRADIUSIndexLongestPrefix(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: wide
    priority: 10
    match:
      source_cidrs: ["10.0.0.0/8", "2001:db8::/32"]
    endpoints:
      - id: r-wide
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: /run/secrets/a}
  - id: narrow
    priority: 50
    match:
      source_cidrs: ["10.1.2.0/24"]
    endpoints:
      - id: r-narrow
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := acc.Match(net.ParseIP("10.1.2.9"))
	if err != nil || got != "narrow" {
		t.Fatalf("v4 lpm=%q err=%v", got, err)
	}
	got, _, err = acc.Match(net.ParseIP("10.9.0.1"))
	if err != nil || got != "wide" {
		t.Fatalf("v4 wide=%q err=%v", got, err)
	}
	acct, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccounting, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err = acct.Match(net.ParseIP("10.1.2.9"))
	if err != nil || got != "wide" {
		t.Fatalf("accounting does not include narrow: %q err=%v", got, err)
	}
	got, _, err = acc.Match(net.ParseIP("2001:db8::5"))
	if err != nil || got != "wide" {
		t.Fatalf("v6=%q err=%v", got, err)
	}
}

func TestRADIUSIndexUnknownSource(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: one
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = idx.Match(net.ParseIP("198.51.100.1"))
	if err == nil {
		t.Fatal("expected no match")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkRADIUSClientLookupIPv4(b *testing.B) {
	clients := make([]Client, 64)
	for i := range clients {
		clients[i] = Client{
			ID:       "c" + itoa(i),
			Priority: i,
			Enabled:  true,
			Match:    ClientMatch{SourceCIDRs: []string{"10." + itoa(i) + ".0.0/16"}},
			Endpoints: []ClientEndpoint{{
				ID:        "r",
				Protocol:  domain.ProtocolRADIUS,
				Transport: EndpointTransportUDP,
				Roles:     []domain.ListenerRole{domain.RoleAccess},
				RADIUS:    &RADIUSEndpoint{SharedSecret: SecretRef{File: "/x"}},
			}},
		}
	}
	idx, err := CompileRADIUSIndex(clients, domain.RoleAccess, domain.CarrierRADIUSUDP)
	if err != nil {
		b.Fatal(err)
	}
	ip := net.ParseIP("10.3.1.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := idx.Match(ip); err != nil {
			b.Fatal(err)
		}
	}
}

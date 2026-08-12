package config

import (
	"net"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func mustParseCIDRClients(t *testing.T, src string) []Client {
	t.Helper()
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return doc.Clients
}

func TestClientIndexV4V6LongestPrefix(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: wide
    priority: 10
    match:
      source_cidrs: ["10.0.0.0/8", "2001:db8::/32"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/a}
  - id: v4-narrow
    priority: 50
    match:
      source_cidrs: ["10.1.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/b}
  - id: v6-narrow
    priority: 50
    match:
      source_cidrs: ["2001:db8:1::/48"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/c}
`)
	idx, err := CompileClientIndex(clients)
	if err != nil {
		t.Fatal(err)
	}
	got, err := idx.Match(domain.TransportLegacy, net.ParseIP("10.1.2.9"), nil)
	if err != nil || got != "v4-narrow" {
		t.Fatalf("v4 lpm=%q err=%v", got, err)
	}
	got, err = idx.Match(domain.TransportLegacy, net.ParseIP("10.9.0.1"), nil)
	if err != nil || got != "wide" {
		t.Fatalf("v4 wide=%q err=%v", got, err)
	}
	got, err = idx.Match(domain.TransportLegacy, net.ParseIP("2001:db8:1::5"), nil)
	if err != nil || got != "v6-narrow" {
		t.Fatalf("v6 lpm=%q err=%v", got, err)
	}
	got, err = idx.Match(domain.TransportLegacy, net.ParseIP("2001:db8:2::1"), nil)
	if err != nil || got != "wide" {
		t.Fatalf("v6 wide=%q err=%v", got, err)
	}
}

func TestClientIndexAmbiguousSamePrefixAndPriority(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: zebra
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/a}
  - id: alpha
    priority: 10
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/b}
`)
	_, err := CompileClientIndex(clients)
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
	if strings.Contains(err.Error(), "zebra and alpha") {
		t.Fatal("ids in the message must be sorted; lex-ID is not a match key")
	}
}

func TestClientIndexDifferentPrioritySameCIDROK(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: low
    priority: 1
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/a}
  - id: high
    priority: 100
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/b}
`)
	idx, err := CompileClientIndex(clients)
	if err != nil {
		t.Fatal(err)
	}
	got, err := idx.Match(domain.TransportLegacy, net.ParseIP("192.0.2.10"), nil)
	if err != nil || got != "low" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestClientIndexCertificateOnlyIgnoresCIDR(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: cert-a
    priority: 20
    match:
      mode: certificate_only
      source_cidrs: ["10.0.0.0/8"]
      transports: [tls]
      certificate:
        dns_sans: ["nas.lab.example"]
  - id: addr
    priority: 10
    match:
      source_cidrs: ["10.1.0.0/16"]
      transports: [tls]
      certificate:
        dns_sans: ["other.lab.example"]
`)
	idx, err := CompileClientIndex(clients)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Warnings()) == 0 {
		t.Fatal("certificate_only source_cidrs should warn")
	}
	cert := &CertIdentity{DNSSANs: []string{"nas.lab.example"}}
	// CIDR 192.0.2.1 is outside 10.0.0.0/8; certificate_only still matches.
	got, err := idx.Match(domain.TransportTLS, net.ParseIP("192.0.2.1"), cert)
	if err != nil || got != "cert-a" {
		t.Fatalf("cert-only=%q err=%v", got, err)
	}
	addrCert := &CertIdentity{DNSSANs: []string{"other.lab.example"}}
	got, err = idx.Match(domain.TransportTLS, net.ParseIP("10.1.9.9"), addrCert)
	if err != nil || got != "addr" {
		t.Fatalf("addr=%q err=%v", got, err)
	}
}

func TestClientIndexCertificateOnlyTieIsAmbiguous(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: a
    priority: 5
    match:
      mode: certificate_only
      transports: [tls]
      certificate:
        dns_sans: ["shared.lab.example"]
  - id: b
    priority: 5
    match:
      mode: certificate_only
      transports: [tls]
      certificate:
        dns_sans: ["shared.lab.example"]
`)
	_, err := CompileClientIndex(clients)
	if err == nil {
		t.Fatal("expected ambiguity")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("%v", err)
	}
}

func TestClientIndexTransportAndDisabled(t *testing.T) {
	t.Parallel()
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: tls-only
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [tls]
  - id: off
    enabled: false
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/x}
  - id: on
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/y}
`)
	idx, err := CompileClientIndex(clients)
	if err != nil {
		t.Fatal(err)
	}
	got, err := idx.Match(domain.TransportLegacy, net.ParseIP("10.0.0.1"), nil)
	if err != nil || got != "on" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	_, err = idx.Match(domain.TransportLegacy, net.ParseIP("192.0.2.1"), nil)
	if err == nil {
		t.Fatal("expected no match")
	}
}

func TestClientIndexNoLexicographicTieBreakAtRuntime(t *testing.T) {
	t.Parallel()
	// Distinct cert names so compile succeeds; a dual-SAN peer still ties.
	clients := mustParseCIDRClients(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: aaa
    priority: 1
    match:
      mode: certificate_only
      transports: [tls]
      certificate:
        dns_sans: ["one.lab.example"]
  - id: zzz
    priority: 1
    match:
      mode: certificate_only
      transports: [tls]
      certificate:
        dns_sans: ["two.lab.example"]
`)
	idx, err := CompileClientIndex(clients)
	if err != nil {
		t.Fatal(err)
	}
	_, err = idx.Match(domain.TransportTLS, net.ParseIP("192.0.2.1"), &CertIdentity{
		DNSSANs: []string{"one.lab.example", "two.lab.example"},
	})
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("runtime tie must fail closed, got %v", err)
	}
}

func TestCheckSharedSecretPolicy(t *testing.T) {
	t.Parallel()
	policy := SharedSecretPolicy{
		MinimumLengthCharacters: 16,
		MinimumCharacterClasses: 3,
		RejectKnownWeakValues:   true,
	}
	if err := CheckSharedSecret(policy, credentials.NewSharedSecret([]byte("short")), "p"); err == nil {
		t.Fatal("short")
	} else if de, _ := domain.AsError(err); de.Code != domain.CodeSharedSecretPolicyViolation {
		t.Fatalf("%v", err)
	}
	if err := CheckSharedSecret(policy, credentials.NewSharedSecret([]byte("password")), "p"); err == nil {
		t.Fatal("weak")
	}
	long := []byte("Abcdefghijklmnop12!!-this-is-over-thirty-two-bytes-long")
	if err := CheckSharedSecret(policy, credentials.NewSharedSecret(long), "p"); err != nil {
		t.Fatal(err)
	}
	if err := CheckSharedSecret(policy, credentials.NewSharedSecret([]byte("alllowercaseletters")), "p"); err == nil {
		t.Fatal("classes")
	}
	err := CheckSharedSecret(policy, credentials.NewSharedSecret([]byte("password")), "p")
	if err != nil && strings.Contains(err.Error(), "password") {
		t.Fatalf("weak value echoed: %v", err)
	}
}

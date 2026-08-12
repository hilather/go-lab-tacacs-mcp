package state

import (
	"net"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestSnapshotMatchV4V6LPM(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: wide
    priority: 10
    match:
      source_cidrs: ["10.0.0.0/8", "2001:db8::/32"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/a}}
  - id: v4-narrow
    priority: 50
    match:
      source_cidrs: ["10.1.2.0/24"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/b}}
  - id: v6-narrow
    priority: 50
    match:
      source_cidrs: ["2001:db8:1::/48"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/c}}
`)
	s := m.Snapshot()
	c, err := s.MatchClient(domain.TransportLegacy, net.ParseIP("10.1.2.9"), nil)
	if err != nil || c.Client.ID != "v4-narrow" {
		t.Fatalf("v4=%s err=%v", c.Client.ID, err)
	}
	c, err = s.MatchClient(domain.TransportLegacy, net.ParseIP("2001:db8:1::aa"), nil)
	if err != nil || c.Client.ID != "v6-narrow" {
		t.Fatalf("v6=%s err=%v", c.Client.ID, err)
	}
}

func TestSnapshotRejectsAmbiguousClients(t *testing.T) {
	t.Parallel()
	_, err := New(mustParse(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: a
    priority: 1
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/a}}
  - id: b
    priority: 1
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy: {shared_secret: {file: /run/secrets/b}}
`), Options{})
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
}

func TestSnapshotCertificateOnly(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: cert
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
	s := m.Snapshot()
	c, err := s.MatchClient(domain.TransportTLS, net.ParseIP("198.51.100.1"), &config.CertIdentity{
		DNSSANs: []string{"nas.lab.example"},
	})
	if err != nil || c.Client.ID != "cert" {
		t.Fatalf("cert-only=%s err=%v", c.Client.ID, err)
	}
}

func TestOverlayAmbiguousClientNotPublished(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	before := m.Snapshot()
	rev := before.Revision
	match := before.Clients()[0].Client.Match
	_, err := m.CreateClient(CreateClient{
		ID:           "dup",
		Priority:     intPtr(100),
		Match:        &match,
		SharedSecret: &SecretPatch{Ref: before.Clients()[0].Client.Legacy.SharedSecret},
	}, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("ambiguous overlay must not publish")
	}
}

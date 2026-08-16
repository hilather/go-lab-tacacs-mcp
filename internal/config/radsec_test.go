package config

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestRadSecListenerDefaultsOff(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_defaults.yaml")
	rs := doc.Listeners.RADIUSRadSec
	if rs.Enabled || rs.Required {
		t.Fatalf("radsec must default off: %+v", rs)
	}
	if rs.Bind != "0.0.0.0:2083" {
		t.Fatalf("bind=%q", rs.Bind)
	}
	if rs.Transport != EndpointTransportTLS {
		t.Fatalf("transport=%q", rs.Transport)
	}
	if rs.MaxPacketBytes != RADIUSMaxPacketBytes {
		t.Fatalf("max_packet_bytes=%d", rs.MaxPacketBytes)
	}
	if rs.MaxConnections != 256 {
		t.Fatalf("max_connections=%d", rs.MaxConnections)
	}
	if rs.IdleTimeout != 60*time.Second || rs.HandshakeTimeout != 10*time.Second {
		t.Fatalf("timeouts idle=%s hs=%s", rs.IdleTimeout, rs.HandshakeTimeout)
	}
	if rs.TLS.MinimumVersion != "TLS1.3" {
		t.Fatalf("tls min=%q", rs.TLS.MinimumVersion)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
}

func TestRADIUSTransportTLSAndUDPPerCarrier(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: mixed
    match:
      source_cidrs: ["192.0.2.0/24"]
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: /run/secrets/udp}
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access, accounting]
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
	c := doc.Clients[0]
	udp := radiusEndpoint(c, EndpointTransportUDP)
	tls := radiusEndpoint(c, EndpointTransportTLS)
	if udp == nil || udp.ID != "radius-udp" || udp.RADIUS.SharedSecret.Purpose != credentials.PurposeRADIUSSharedSecret {
		t.Fatalf("udp=%+v", udp)
	}
	if tls == nil || tls.ID != "radius-tls" {
		t.Fatalf("tls=%+v", tls)
	}
	if !hasRADIUSEndpoint(c) || !hasRADIUSTLSEndpoint(c) {
		t.Fatal("expected both carriers")
	}
	if got := radiusEndpoints(c); len(got) != 2 {
		t.Fatalf("endpoints=%d", len(got))
	}
}

func TestAtMostOneRADIUSEndpointPerCarrier(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: rad
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: a
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
      - id: b
        protocol: radius
        transport: tls
        roles: [accounting]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	_, err := Parse(src)
	if err == nil || !strings.Contains(err.Error(), "at most one RADIUS") {
		t.Fatalf("got %v", err)
	}
}

func TestCleartextRADIUSTCPRejected(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: rad
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r
        protocol: radius
        transport: tcp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/r}
`)
	_, err := Parse(src)
	if err == nil || !strings.Contains(err.Error(), "udp or tls") {
		t.Fatalf("got %v", err)
	}
}

func TestCertificateOnlyLegalWithRADIUSTLS(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: radsec
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: radius-tls
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/r}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
	if radiusEndpoint(doc.Clients[0], EndpointTransportUDP) != nil {
		t.Fatal("TLS-only client must not have a UDP RADIUS endpoint")
	}
}

func TestCertificateOnlyStillRequiresTLSEndpoint(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: rad
    match:
      mode: certificate_only
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/r}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateV2(doc)
	if err == nil {
		t.Fatal("expected certificate_only reject")
	}
	if !strings.Contains(err.Error(), "certificate_only") {
		t.Fatalf("%v", err)
	}
}

func TestRADIUSTLSSecretStillRequired(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: rad
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: r
        protocol: radius
        transport: tls
        roles: [access]
        radius: {}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateV2(doc)
	if err == nil {
		t.Fatal("expected missing secret")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeRADIUSSecretMissing {
		t.Fatalf("got %v", err)
	}
}

func TestRADIUSTLSDoesNotDefaultSecretRadsec(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: rad
    match:
      mode: certificate_only
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: r
        protocol: radius
        transport: tls
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/r}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	ep := radiusEndpoint(doc.Clients[0], EndpointTransportTLS)
	if ep == nil || !ep.RADIUS.SharedSecret.Set() {
		t.Fatal("secret ref must remain required and explicit")
	}
	if strings.Contains(strings.ToLower(ep.RADIUS.SharedSecret.File), "radsec") && ep.RADIUS.SharedSecret.File == "radsec" {
		t.Fatal("must not special-case the string radsec")
	}
}

func TestTLSOnlyClientHasNoUDPEndpointForDAC(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: tls-only
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
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
	if ep := radiusEndpoint(doc.Clients[0], EndpointTransportUDP); ep != nil {
		t.Fatal("DAC must reject TLS-only clients: no UDP RADIUS endpoint")
	}
}

func TestV1RejectsRadSecListenerKey(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("schema_version: 1\nlisteners:\n  radius:\n    radsec:\n      enabled: true\n"))
	if err == nil {
		t.Fatal("expected v1 reject")
	}
	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("got %v", err)
	}
	if de.Code != domain.CodeConfigUnknownField && de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestRadSecListenerRejectsCleartextTransport(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    radsec:
      transport: tcp
`)
	_, err := Parse(src)
	if err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("got %v", err)
	}
}

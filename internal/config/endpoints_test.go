package config

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestV2ParsesRADIUSEndpoints(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_endpoints.yaml")
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Clients) != 1 {
		t.Fatalf("clients=%d", len(doc.Clients))
	}
	c := doc.Clients[0]
	if len(c.Endpoints) != 2 {
		t.Fatalf("endpoints=%d", len(c.Endpoints))
	}
	if !hasTransport(c.Match.Transports, domain.TransportLegacy) {
		t.Fatalf("TACACS projection missing legacy: %v", c.Match.Transports)
	}
	if c.Legacy.SharedSecret.Purpose != credentials.PurposeLegacySharedSecret || c.Legacy.SharedSecret.File == "" {
		t.Fatalf("legacy projection=%+v", c.Legacy.SharedSecret)
	}
	rad := radiusEndpoint(c)
	if rad == nil || rad.RADIUS == nil {
		t.Fatal("missing RADIUS endpoint")
	}
	if rad.RADIUS.SharedSecret.Purpose != credentials.PurposeRADIUSSharedSecret {
		t.Fatalf("purpose=%s", rad.RADIUS.SharedSecret.Purpose)
	}
	if !rad.RADIUS.RequireMessageAuthenticator || !rad.RADIUS.LimitProxyState {
		t.Fatalf("ma defaults %+v", rad.RADIUS)
	}
	if len(rad.RADIUS.AllowedAuthenticationMethods) != 2 {
		t.Fatalf("methods=%v", rad.RADIUS.AllowedAuthenticationMethods)
	}
	if rad.RADIUS.AccessPolicyID != "default-radius-access" {
		t.Fatalf("policy=%q", rad.RADIUS.AccessPolicyID)
	}
}

func TestV1SynthesizesTACACSEndpoints(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v1_tacacs_equivalent.yaml")
	if len(doc.Clients) != 1 || len(doc.Clients[0].Endpoints) != 1 {
		t.Fatalf("endpoints=%+v", doc.Clients[0].Endpoints)
	}
	ep := doc.Clients[0].Endpoints[0]
	if ep.ID != "tacacs-legacy" || ep.Protocol != domain.ProtocolTACACS || ep.Transport != EndpointTransportTCP {
		t.Fatalf("ep=%+v", ep)
	}
	if ep.TACACS == nil || ep.TACACS.SharedSecret.File == "" {
		t.Fatal("synthesized TACACS secret")
	}
	if err := checkClientProjection(doc.Clients[0], "clients[0]"); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateOnlyRequiresTACACSTLS(t *testing.T) {
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
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "certificate_only") {
		t.Fatalf("%v", err)
	}
}

func TestCertificateOnlyOKWithTACACSTLS(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: mixed
    match:
      mode: certificate_only
      source_cidrs: ["192.0.2.0/24"]
      certificate:
        dns_sans: ["nas.lab.example"]
    endpoints:
      - id: tacacs-tls
        protocol: tacacs
        transport: tls
        roles: [authentication, authorization, accounting]
      - id: radius-udp
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
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
}

func TestProjectionMismatchRejected(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_endpoints.yaml")
	doc.Clients[0].Match.Transports = []domain.Transport{domain.TransportTLS}
	err := ValidateV2(doc)
	if err == nil {
		t.Fatal("expected projection mismatch")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientEndpointProjectionMismatch {
		t.Fatalf("got %v", err)
	}
}

func TestFlattenAndEndpointsDisagree(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: sw
    match:
      source_cidrs: ["192.0.2.0/24"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/flatten}
    endpoints:
      - id: tacacs-legacy
        protocol: tacacs
        transport: tcp
        roles: [authentication, authorization, accounting]
        tacacs:
          shared_secret: {file: /run/secrets/other}
`)
	_, err := Parse(src)
	if err == nil {
		t.Fatal("expected projection mismatch")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientEndpointProjectionMismatch {
		t.Fatalf("got %v", err)
	}
}

func TestRADIUSSecretMissing(t *testing.T) {
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
        transport: udp
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

func TestAtMostOneRADIUSEndpoint(t *testing.T) {
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
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/a}
      - id: b
        protocol: radius
        transport: udp
        roles: [accounting]
        radius:
          shared_secret: {file: /run/secrets/b}
`)
	_, err := Parse(src)
	if err == nil || !strings.Contains(err.Error(), "at most one RADIUS") {
		t.Fatalf("got %v", err)
	}
}

func TestV1StillRejectsEndpoints(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("schema_version: 1\nclients:\n  - id: sw\n    endpoints:\n      - id: r\n        protocol: radius\n"))
	if err == nil {
		t.Fatal("expected unknown field")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigUnknownField {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "endpoints") {
		t.Fatalf("path=%q", de.Path)
	}
}

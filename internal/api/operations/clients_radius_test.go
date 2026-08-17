package operations

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

const mixedRADIUSClientYAML = `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: lab-switches
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: tacacs-legacy
        protocol: tacacs
        transport: tcp
        roles: [authentication, authorization, accounting]
        tacacs:
          shared_secret: {file: /run/secrets/lab_switches_tacacs_secret}
          allowed_methods: [ascii, pap]
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: /run/secrets/lab_switches_radius_secret}
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [pap, chap]
`

func TestClientViewIncludesRADIUSBlock(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	reader := Actor{ID: "r", Scopes: []string{"state:read"}}
	got, err := reg.Invoke(context.Background(), IDClientsGet, m.Snapshot(), Input{
		Actor: reader, Request: GetClientRequest{ID: "lab-switches"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := got.Data.(Client)
	if !c.Protocols.RADIUS.Enabled {
		t.Fatalf("radius view disabled: %+v", c.Protocols)
	}
	if !c.Protocols.RADIUS.SharedSecretConfigured || !c.Protocols.TACACS.LegacyEnabled {
		t.Fatalf("protocols=%+v", c.Protocols)
	}
	if !c.Protocols.RADIUS.RequireMessageAuthenticator || !c.Protocols.RADIUS.LimitProxyState {
		t.Fatalf("radius flags=%+v", c.Protocols.RADIUS)
	}
	if len(c.Endpoints) != 2 {
		t.Fatalf("endpoints=%d", len(c.Endpoints))
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "/run/secrets/lab_switches_radius_secret") {
		t.Fatalf("radius secret path leaked: %s", raw)
	}
}

func TestClientRADIUSFlattenCreateUpdate(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	created, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "rad",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.9.0.0/16"},
				Transports:  []string{"legacy"},
			},
			SharedSecret: OptionalSecret{Present: true, File: "/run/secrets/rad-tacacs"},
			RADIUS: &ClientRADIUSWrite{
				SharedSecret: OptionalSecret{Present: true, File: "/run/secrets/rad-radius"},
				Roles:        []string{"access", "accounting"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := created.Data.(Client)
	if !c.Protocols.RADIUS.Enabled || !c.Protocols.RADIUS.SharedSecretConfigured {
		t.Fatalf("create radius=%+v", c.Protocols.RADIUS)
	}
	if !c.SharedSecretConfigured {
		t.Fatal("TACACS secret dropped on RADIUS create")
	}
	rev := created.Revision
	reqMA := true
	updated, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID:     "rad",
			RADIUS: &ClientRADIUSWrite{RequireMessageAuthenticator: &reqMA},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := updated.Data.(Client)
	if !got.Protocols.RADIUS.RequireMessageAuthenticator {
		t.Fatalf("require_ma=%+v", got.Protocols.RADIUS)
	}
	if !got.Protocols.RADIUS.SharedSecretConfigured {
		t.Fatal("omitted RADIUS secret dropped")
	}
}

func TestClientFlattenPatchResynthesizesEndpoints(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	updated, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID:             "sw",
			Authentication: &ClientAuthView{AllowedMethods: []string{"ascii"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := updated.Data.(Client)
	if len(c.Authentication.AllowedMethods) != 1 || c.Authentication.AllowedMethods[0] != "ascii" {
		t.Fatalf("flatten auth=%+v", c.Authentication)
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].ID != "tacacs-legacy" || c.Endpoints[0].TACACS == nil {
		t.Fatalf("endpoints=%+v", c.Endpoints)
	}
	if len(c.Endpoints[0].TACACS.AllowedMethods) != 1 || c.Endpoints[0].TACACS.AllowedMethods[0] != "ascii" {
		t.Fatalf("endpoint methods=%v", c.Endpoints[0].TACACS.AllowedMethods)
	}

	rev = updated.Revision
	switched, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID: "sw",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.20.0.0/16", "2001:db8:20::/48"},
				Transports:  []string{"tls"},
			},
			SharedSecret: OptionalSecret{Present: true, Clear: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := switched.Data.(Client)
	if len(got.Endpoints) != 1 || got.Endpoints[0].ID != "tacacs-tls" || got.Endpoints[0].Transport != "tls" {
		t.Fatalf("tls endpoints=%+v", got.Endpoints)
	}
	if got.Protocols.TACACS.LegacyEnabled || !got.Protocols.TACACS.TLSEnabled {
		t.Fatalf("protocols=%+v", got.Protocols.TACACS)
	}
}

func TestClientEndpointsRADIUSOmitsMethodsDefaultsPAPCHAP(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	created, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "rad-omit-methods",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.30.0.0/16"},
			},
			Endpoints: &[]ClientEndpointWrite{{
				ID:        "radius-udp",
				Protocol:  "radius",
				Transport: "udp",
				Roles:     []string{"access"},
				RADIUS: &ClientRADIUSWrite{
					SharedSecret: OptionalSecret{Present: true, File: "/run/secrets/rad-omit"},
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := created.Data.(Client)
	if len(c.Endpoints) != 1 || c.Endpoints[0].RADIUS == nil {
		t.Fatalf("endpoints=%+v", c.Endpoints)
	}
	got := c.Endpoints[0].RADIUS.AllowedMethods
	if strings.Join(got, ",") != "pap,chap" {
		t.Fatalf("omitted methods persisted %v, want pap,chap", got)
	}
	for _, method := range got {
		if method == "eap" || method == "peap" {
			t.Fatal("eap/peap must stay opt-in")
		}
	}

	eff, ok := m.Snapshot().Client("rad-omit-methods")
	if !ok || len(eff.Client.Endpoints) != 1 || eff.Client.Endpoints[0].RADIUS == nil {
		t.Fatal("missing compiled client")
	}
	methods := append([]string(nil), eff.Client.Endpoints[0].RADIUS.AllowedAuthenticationMethods...)
	if strings.Join(methods, ",") != "pap,chap" {
		t.Fatalf("snapshot methods=%v", methods)
	}

	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	secret := []byte("LabRadius-Secret-32-bytes-ok!!")
	var ra [16]byte
	ra[0] = 0xc1
	ident := append([]byte{2, 1, 0, 14, 1}, []byte("lab-admin")...)
	in := signedRADIUSAccess(t, secret, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeEAPMessage, Value: ident},
	})
	in.AllowedMethods = methods
	in.ClientID = "rad-omit-methods"
	in.EndpointID = "radius-udp"
	in.Peer = netip.MustParseAddrPort("192.0.2.10:1812")
	in.Carrier = domain.CarrierRADIUSUDP
	res := server.Access{Store: store}.Handle(context.Background(), in)
	if res.Action != server.ActionReply || res.Reason != server.ReasonUnsupportedMethod || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("Identity must Reject without Challenge: %+v", res)
	}
	pkt, err := codec.Decode(res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkt.Attributes.First(attribute.TypeState); ok {
		t.Fatal("must not emit State")
	}
	if store.Len() != 0 {
		t.Fatal("must not store State")
	}
}

func signedRADIUSAccess(t *testing.T, secret []byte, ra [16]byte, attrs attribute.RawSet) server.Request {
	t.Helper()
	pkt := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    1,
		Authenticator: ra,
		Attributes:    append(attrs, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)}),
	}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := crypto.MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	off := codec.HeaderSize
	for off+2 <= len(raw) {
		if raw[off] == attribute.TypeMessageAuthenticator {
			copy(raw[off+2:off+18], mac[:])
			break
		}
		off += int(raw[off+1])
	}
	dec, err := codec.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return server.Request{
		Role:                        domain.RoleAccess,
		Packet:                      dec,
		Declared:                    raw,
		Secret:                      secret,
		RequireMessageAuthenticator: true,
	}
}

func TestClientRADIUSWriteRejectsUnknownMethod(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	_, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "bad-rad",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.9.0.0/16"},
			},
			RADIUS: &ClientRADIUSWrite{
				SharedSecret:   OptionalSecret{Present: true, File: "/run/secrets/rad"},
				AllowedMethods: []string{"ttls"},
			},
		},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

func TestClientRADIUSWriteAcceptsPEAP(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	created, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "rad-peap",
			Match: &ClientMatchView{
				SourceCIDRs: []string{"10.10.0.0/16"},
			},
			RADIUS: &ClientRADIUSWrite{
				SharedSecret:   OptionalSecret{Present: true, File: "/run/secrets/rad"},
				AllowedMethods: []string{"peap"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := created.Data.(Client)
	if len(c.Endpoints) == 0 || c.Endpoints[0].RADIUS == nil {
		t.Fatalf("endpoints=%+v", c.Endpoints)
	}
	if strings.Join(c.Endpoints[0].RADIUS.AllowedMethods, ",") != "peap" {
		t.Fatalf("methods=%v", c.Endpoints[0].RADIUS.AllowedMethods)
	}
}

func TestClientRADIUSSecretNullRejected(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	_, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID:     "lab-switches",
			RADIUS: &ClientRADIUSWrite{SharedSecret: OptionalSecret{Present: true, Clear: true}},
		},
	})
	if !isCode(err, domain.CodeRADIUSSecretMissing) {
		t.Fatalf("err=%v", err)
	}
	if m.Revision() != rev {
		t.Fatal("null RADIUS secret published")
	}
}

func TestClientEndpointsDisagreeWithFlatten(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	_, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID: "lab-switches",
			Authentication: &ClientAuthView{
				AllowedMethods: []string{"ascii"},
			},
			Endpoints: &[]ClientEndpointWrite{{
				ID:        "tacacs-legacy",
				Protocol:  "tacacs",
				Transport: "tcp",
				Roles:     []string{"authentication", "authorization", "accounting"},
				TACACS:    &ClientTACACSEndpointWrite{AllowedMethods: []string{"pap"}},
			}},
		},
	})
	if !isCode(err, domain.CodeInvalidArgument) {
		t.Fatalf("err=%v", err)
	}
}

const tlsOnlyRADIUSClientYAML = `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: radsec
    display_name: RadSec NAS
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
          require_message_authenticator: true
          allowed_authentication_methods: [pap, chap]
`

func TestClientEndpointsAcceptRADIUSTransportTLS(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, tlsOnlyRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	created, err := reg.Invoke(context.Background(), IDClientsCreate, m.Snapshot(), Input{
		Actor: writer,
		Request: CreateClientRequest{
			ID: "radsec-api",
			Match: &ClientMatchView{
				Mode: "certificate_only",
				Certificate: CertMatchView{
					DNSSANs: []string{"nas.lab.example"},
				},
			},
			Endpoints: &[]ClientEndpointWrite{{
				ID:        "radius-tls",
				Protocol:  "radius",
				Transport: "tls",
				Roles:     []string{"access"},
				RADIUS: &ClientRADIUSWrite{
					SharedSecret: OptionalSecret{Present: true, File: "/run/secrets/tls"},
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := created.Data.(Client)
	if c.Protocols.RADIUS.Enabled {
		t.Fatal("flatten RADIUS view must stay UDP-only")
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].Transport != "tls" || c.Endpoints[0].Protocol != "radius" {
		t.Fatalf("endpoints=%+v", c.Endpoints)
	}
}

func TestClientTLSOnlyFlattenUpdateDoesNotAddUDP(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, tlsOnlyRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	enabled := true
	updated, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID: "radsec",
			RADIUS: &ClientRADIUSWrite{
				Enabled: &enabled,
				Roles:   []string{"access", "accounting"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := updated.Data.(Client)
	if c.Protocols.RADIUS.Enabled {
		t.Fatal("flatten must not invent a UDP RADIUS endpoint on a TLS-only client")
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].ID != "radius-tls" || c.Endpoints[0].Transport != "tls" {
		t.Fatalf("tls endpoint lost or UDP added: %+v", c.Endpoints)
	}
}

func TestClientTLSOnlyFlattenDisableKeepsTLS(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, tlsOnlyRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	writer := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	rev := m.Revision()
	enabled := false
	updated, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID:     "radsec",
			RADIUS: &ClientRADIUSWrite{Enabled: &enabled},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := updated.Data.(Client)
	if len(c.Endpoints) != 1 || c.Endpoints[0].Transport != "tls" {
		t.Fatalf("flatten disable must not delete TLS RADIUS: %+v", c.Endpoints)
	}
}

func TestClientTLSOnlyViewOmitsFlattenRADIUS(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, tlsOnlyRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	reader := Actor{ID: "r", Scopes: []string{"state:read"}}
	got, err := reg.Invoke(context.Background(), IDClientsGet, m.Snapshot(), Input{
		Actor: reader, Request: GetClientRequest{ID: "radsec"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := got.Data.(Client)
	if c.Protocols.RADIUS.Enabled {
		t.Fatalf("TLS-only flatten view must be disabled: %+v", c.Protocols.RADIUS)
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].Transport != "tls" {
		t.Fatalf("endpoints=%+v", c.Endpoints)
	}
	if c.Endpoints[0].RADIUS == nil || !c.Endpoints[0].RADIUS.Enabled {
		t.Fatalf("TLS endpoint view must still report RADIUS policy: %+v", c.Endpoints[0].RADIUS)
	}
}

func TestExportV1SourceStaysV1UnlessNormalize(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	reader := Actor{ID: "r", Scopes: []string{"state:read", "config:export"}}

	eff, err := reg.Invoke(context.Background(), IDConfigEffectiveGet, m.Snapshot(), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	ec := eff.Data.(EffectiveConfig)
	if ec.SourceSchemaVersion != config.SchemaVersionV1 || ec.EffectiveSchemaVersion != config.SchemaVersionV2 {
		t.Fatalf("effective schema labels=%+v", ec)
	}
	if !ec.Clients[0].Protocols.TACACS.LegacyEnabled || ec.Clients[0].Protocols.RADIUS.Enabled {
		t.Fatalf("v1 client view=%+v", ec.Clients[0].Protocols)
	}

	exp, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	out := exp.Data.(ExportConfigResult)
	if out.Normalized || out.SourceSchemaVersion != config.SchemaVersionV1 {
		t.Fatalf("export meta=%+v", out)
	}
	if !strings.HasPrefix(out.YAML, "schema_version: 1\n") {
		t.Fatalf("v1 export missing schema 1:\n%s", out.YAML)
	}
	if strings.Contains(out.YAML, "endpoints:") {
		t.Fatalf("v1 export reshaped to v2:\n%s", out.YAML)
	}
	if !strings.Contains(out.YAML, "source_schema_version: 1") || !strings.Contains(out.YAML, "effective_schema_version: 2") {
		t.Fatalf("export missing schema labels:\n%s", out.YAML)
	}

	conv, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{
		Actor: reader, Request: ExportConfigRequest{Normalize: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2 := conv.Data.(ExportConfigResult)
	if !v2.Normalized || !strings.HasPrefix(v2.YAML, "schema_version: 2\n") || !strings.Contains(v2.YAML, "endpoints:") {
		t.Fatalf("normalize export not v2:\n%s", v2.YAML)
	}
}

func TestExportV2SourceEmitsV2(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSClientYAML)
	reg := mustStateRegistry(t, m)
	reader := Actor{ID: "r", Scopes: []string{"config:export"}}
	exp, err := reg.Invoke(context.Background(), IDConfigExport, m.Snapshot(), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	out := exp.Data.(ExportConfigResult)
	if out.SourceSchemaVersion != config.SchemaVersionV2 || !out.Normalized {
		t.Fatalf("v2 export meta=%+v", out)
	}
	if !strings.HasPrefix(out.YAML, "schema_version: 2\n") || !strings.Contains(out.YAML, "protocol: radius") {
		t.Fatalf("v2 export missing radius endpoints:\n%s", out.YAML)
	}
	if strings.Contains(out.YAML, "/run/secrets/lab_switches_radius_secret") {
		t.Fatalf("export leaked radius secret path:\n%s", out.YAML)
	}
}

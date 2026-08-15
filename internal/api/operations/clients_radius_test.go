package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
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
	policy := "default-radius-access"
	updated, err := reg.Invoke(context.Background(), IDClientsUpdate, m.Snapshot(), Input{
		Actor:            writer,
		ExpectedRevision: &rev,
		Request: UpdateClientRequest{
			ID:     "rad",
			RADIUS: &ClientRADIUSWrite{AccessPolicyID: &policy},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := updated.Data.(Client)
	if got.Protocols.RADIUS.AccessPolicyID != policy {
		t.Fatalf("policy=%q", got.Protocols.RADIUS.AccessPolicyID)
	}
	if !got.Protocols.RADIUS.SharedSecretConfigured {
		t.Fatal("omitted RADIUS secret dropped")
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

package operations

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
)

type stubRuntime struct {
	rows []runtime.Status
}

func (s stubRuntime) Statuses() []runtime.Status { return s.rows }
func (s stubRuntime) Ready() bool                { return true }

func TestStatusAppendsConfiguredRADIUSListeners(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t)
	snap := mustSnap(t, radiusStatusYAML)
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, snap, Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Data.(Status)
	if len(st.Listeners) != 5 {
		t.Fatalf("listeners=%d %+v", len(st.Listeners), st.Listeners)
	}
	if st.Listeners[0].ID != ListenerLegacy || st.Listeners[1].ID != ListenerSecure || st.Listeners[2].ID != ListenerHTTP {
		t.Fatalf("order prefix=%+v", st.Listeners)
	}
	access := st.Listeners[3]
	if access.ID != ListenerRADIUSAccess || access.Transport != TransportUDP || access.Protocol != string(domain.ProtocolRADIUS) {
		t.Fatalf("access=%+v", access)
	}
	if access.Carrier != string(domain.CarrierRADIUSUDP) || access.Roles[0] != string(domain.RoleAccess) {
		t.Fatalf("access carrier/role=%+v", access)
	}
	if !access.Enabled || !access.Required || access.Bind != "0.0.0.0:1812" {
		t.Fatalf("access config=%+v", access)
	}
	acct := st.Listeners[4]
	if acct.ID != ListenerRADIUSAccounting || acct.Transport != TransportUDP || acct.Roles[0] != string(domain.RoleAccounting) {
		t.Fatalf("acct=%+v", acct)
	}
	if access.Transport == string(domain.TransportLegacy) || access.Transport == string(domain.TransportTLS) {
		t.Fatal("RADIUS transport leaked onto domain.Transport")
	}
}

func TestStatusOverlaysLiveRuntimeStats(t *testing.T) {
	t.Parallel()
	reg, err := New(mustSpec(t), Deps{
		Build: BuildMeta{Version: "test"},
		Runtime: stubRuntime{rows: []runtime.Status{
			{
				Descriptor: runtime.Descriptor{
					ID:       ListenerLegacy,
					Protocol: domain.ProtocolTACACS,
					Carrier:  domain.CarrierTACACSLegacyTCP,
					Roles:    []domain.ListenerRole{domain.RoleAAA},
					Bind:     "127.0.0.1:4949",
					Required: true,
				},
				Enabled:    true,
				Ready:      true,
				Inflight:   3,
				QueueDepth: 0,
			},
			{
				Descriptor: runtime.Descriptor{
					ID:       ListenerRADIUSAccess,
					Protocol: domain.ProtocolRADIUS,
					Carrier:  domain.CarrierRADIUSUDP,
					Roles:    []domain.ListenerRole{domain.RoleAccess},
					Bind:     "0.0.0.0:1812",
					Required: true,
				},
				Enabled:       true,
				Ready:         true,
				Inflight:      2,
				QueueDepth:    7,
				LastErrorCode: "",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Invoke(context.Background(), IDSystemStatusGet, mustSnap(t, smallYAML), Input{Actor: reader})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Data.(Status)
	if len(st.Listeners) != 4 {
		t.Fatalf("expected 3 snapshot + 1 live RADIUS, got %d %+v", len(st.Listeners), st.Listeners)
	}
	legacy := st.Listeners[0]
	if !legacy.Ready || legacy.Inflight != 3 || !legacy.Required {
		t.Fatalf("legacy live overlay=%+v", legacy)
	}
	if legacy.Bind == "127.0.0.1:4949" {
		t.Fatalf("snapshot bind should win: %q", legacy.Bind)
	}
	if legacy.Transport != string(domain.TransportLegacy) {
		t.Fatalf("TACACS transport changed: %q", legacy.Transport)
	}
	rad := st.Listeners[3]
	if rad.ID != ListenerRADIUSAccess || !rad.Ready || rad.Inflight != 2 || rad.QueueDepth != 7 {
		t.Fatalf("radius live=%+v", rad)
	}
	if rad.Transport != TransportUDP {
		t.Fatalf("radius transport=%q", rad.Transport)
	}
}

const radiusStatusYAML = `
schema_version: 2
server:
  instance_id: lab-radius
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access: {enabled: true, required: true, bind: 0.0.0.0:1812}
    accounting: {enabled: true, bind: 0.0.0.0:1813}
clients:
  - id: sw
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
          shared_secret: {file: /run/secrets/sw}
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access, accounting]
        radius:
          shared_secret: {file: /run/secrets/sw-radius}
          require_message_authenticator: true
          limit_proxy_state: true
          allowed_authentication_methods: [pap, chap]
`

package state

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const mixedRADIUSYAML = `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access: {enabled: true, bind: 0.0.0.0:1812}
    accounting: {enabled: true, bind: 0.0.0.0:1813}
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
          default_service: login
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

func TestV1TACACSSnapshotEquivalent(t *testing.T) {
	t.Parallel()
	v1 := mustParseFile(t, filepath.Join("..", "config", "testdata", "parse", "v1_tacacs_equivalent.yaml"))
	v2 := mustParseFile(t, filepath.Join("..", "config", "testdata", "parse", "v2_tacacs_equivalent.yaml"))
	m1, err := New(v1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := New(v2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s1, s2 := m1.Snapshot(), m2.Snapshot()
	if s1.BaselineHash != s2.BaselineHash {
		t.Fatalf("v1/v2 TACACS baseline hashes differ: %s vs %s", s1.BaselineHash, s2.BaselineHash)
	}
	if !reflect.DeepEqual(tacacsUsers(s1), tacacsUsers(s2)) {
		t.Fatalf("users differ:\n%#v\n%#v", tacacsUsers(s1), tacacsUsers(s2))
	}
	if !reflect.DeepEqual(tacacsGroups(s1), tacacsGroups(s2)) {
		t.Fatalf("groups differ")
	}
	if !reflect.DeepEqual(tacacsClients(s1), tacacsClients(s2)) {
		t.Fatalf("TACACS client fields differ:\n%#v\n%#v", tacacsClients(s1), tacacsClients(s2))
	}
	c1, err := s1.MatchClient(domain.TransportLegacy, net.ParseIP("192.0.2.10"), nil)
	if err != nil || c1.Client.ID != "sw" {
		t.Fatalf("v1 match=%s err=%v", c1.Client.ID, err)
	}
	c2, err := s2.MatchClient(domain.TransportLegacy, net.ParseIP("192.0.2.10"), nil)
	if err != nil || c2.Client.ID != "sw" {
		t.Fatalf("v2 match=%s err=%v", c2.Client.ID, err)
	}
	assertRADIUSIndexEmpty(t, s1)
	assertRADIUSIndexEmpty(t, s2)
	if s1.DictionaryVersion() != "builtin-mvp-1" || s1.Dictionary().Empty() {
		t.Fatalf("v1 dictionary version=%q empty=%v", s1.DictionaryVersion(), s1.Dictionary().Empty())
	}
}

func TestV1SnapshotRADIUSIndexesEmpty(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	s := m.Snapshot()
	if s.RADIUSAccessIndex() == nil || s.RADIUSAccountingIndex() == nil || s.RADIUSDynAuthIndex() == nil {
		t.Fatal("v1 snapshot must still carry RADIUS indexes")
	}
	assertRADIUSIndexEmpty(t, s)
	if s.ClientIndex() == nil {
		t.Fatal("TACACS index missing")
	}
	c, err := s.MatchClient(domain.TransportLegacy, net.ParseIP("10.20.1.9"), nil)
	if err != nil || c.Client.ID != "sw" {
		t.Fatalf("TACACS match=%s err=%v", c.Client.ID, err)
	}
	u, ok := s.User("alice")
	if !ok || u.User.Credentials.Login.Verifier.File != "/run/secrets/alice-login" {
		t.Fatalf("v1 user mutated: %+v", u.User.Credentials.Login.Verifier)
	}
}

func TestCompiledAccessEndpointsNeverHaveEmptyMethods(t *testing.T) {
	t.Parallel()
	src := `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access: {enabled: true, bind: 0.0.0.0:1812}
clients:
  - id: lab-switches
    priority: 100
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/lab_switches_radius_secret}
`
	m := mustMgr(t, src)
	for _, ec := range m.Snapshot().Clients() {
		for _, ep := range ec.Client.Endpoints {
			if ep.Protocol != domain.ProtocolRADIUS || ep.RADIUS == nil {
				continue
			}
			hasAccess := false
			for _, r := range ep.Roles {
				if r == domain.RoleAccess {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				continue
			}
			if len(ep.RADIUS.AllowedAuthenticationMethods) == 0 {
				t.Fatalf("compiled access endpoint %s has empty methods", ep.ID)
			}
		}
	}
}

func TestSnapshotCompilesRADIUSIndexes(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	s := m.Snapshot()
	if s.RADIUSAccessIndex() == nil || s.RADIUSAccountingIndex() == nil || s.RADIUSDynAuthIndex() == nil {
		t.Fatal("missing RADIUS indexes")
	}
	if s.RADIUSAccessIndex().Role() != domain.RoleAccess || s.RADIUSAccountingIndex().Role() != domain.RoleAccounting {
		t.Fatalf("roles access=%s acct=%s", s.RADIUSAccessIndex().Role(), s.RADIUSAccountingIndex().Role())
	}
	if s.RADIUSDynAuthIndex().Role() != domain.RoleDynamicAuthorization {
		t.Fatalf("dynauth role=%s", s.RADIUSDynAuthIndex().Role())
	}
	c, epid, err := s.MatchRADIUS(domain.RoleAccess, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err != nil || c.Client.ID != "lab-switches" || epid != "radius-udp" {
		t.Fatalf("access=%s ep=%s err=%v", c.Client.ID, epid, err)
	}
	c, epid, err = s.MatchRADIUS(domain.RoleAccounting, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err != nil || c.Client.ID != "lab-switches" || epid != "radius-udp" {
		t.Fatalf("acct=%s ep=%s err=%v", c.Client.ID, epid, err)
	}
	_, _, err = s.MatchRADIUS(domain.RoleAccess, domain.CarrierRADIUSUDP, net.ParseIP("198.51.100.1"))
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("unknown source: %v", err)
	}
	_, _, err = s.MatchRADIUS(domain.RoleDynamicAuthorization, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err == nil {
		t.Fatal("mixed YAML has no dynamic_authorization role")
	}
	if s.DictionaryVersion() != "builtin-mvp-1" || s.Dictionary().Empty() {
		t.Fatalf("dictionary version=%q empty=%v", s.DictionaryVersion(), s.Dictionary().Empty())
	}
	if s.RADIUSPolicies() == nil {
		t.Fatal("compiled RADIUS policy engine missing")
	}
}

func TestCompiledAccessMethodsNeverEmpty(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	c, ok := m.Snapshot().Client("lab-switches")
	if !ok {
		t.Fatal("missing client")
	}
	for _, ep := range c.Client.Endpoints {
		if ep.RADIUS == nil {
			continue
		}
		if len(ep.RADIUS.AllowedAuthenticationMethods) == 0 {
			t.Fatalf("endpoint %s compiled empty method list", ep.ID)
		}
		for _, method := range ep.RADIUS.AllowedAuthenticationMethods {
			if method == config.RADIUSAuthMethodEAP {
				t.Fatalf("eap must stay opt-in: %v", ep.RADIUS.AllowedAuthenticationMethods)
			}
		}
	}
}

func TestReloadInvalidRADIUSKeepsSnapshot(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	before := m.Snapshot()
	rev := before.Revision
	bad := mustParse(t, `
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
	_, err := m.Reload(bad, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("invalid RADIUS reload must keep previous snapshot")
	}
	if m.Revision() != before.Revision {
		t.Fatalf("revision moved: %d", m.Revision())
	}
	c, _, err := m.Snapshot().MatchRADIUS(domain.RoleAccess, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err != nil || c.Client.ID != "lab-switches" {
		t.Fatalf("previous RADIUS index lost: %s err=%v", c.Client.ID, err)
	}
}

func TestReloadInvalidRADIUSPolicyKeepsSnapshot(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	before := m.Snapshot()
	rev := before.Revision
	bad := mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_reply_profiles:
  - id: bad
    attributes:
      - name: NAS-IP-Address
        value: "192.0.2.1"
radius_policies:
  - id: p
    rules:
      - id: r
        effect: permit
        reply_profiles: [bad]
clients:
  - id: lab-switches
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: /run/secrets/lab_switches_radius_secret}
          access_policy_id: p
`)
	if _, err := m.Reload(bad, &rev); err == nil {
		t.Fatal("illegal reply role must fail compile")
	}
	if m.Snapshot() != before {
		t.Fatal("invalid RADIUS policy compile must keep previous snapshot")
	}
}

func TestOverlayRetainsOmittedRADIUSSecret(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	before, ok := m.Snapshot().Client("lab-switches")
	if !ok {
		t.Fatal("missing client")
	}
	want := radiusSecretFile(before.Client)
	if want == "" {
		t.Fatal("baseline RADIUS secret missing")
	}
	rev := m.Revision()
	snap, err := m.UpdateClient("lab-switches", UpdateClient{DisplayName: strPtr("Switches Prime")}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := snap.Client("lab-switches")
	if !ok {
		t.Fatal("missing after patch")
	}
	if got.Client.DisplayName != "Switches Prime" {
		t.Fatalf("display=%q", got.Client.DisplayName)
	}
	if radiusSecretFile(got.Client) != want {
		t.Fatalf("omitted RADIUS secret dropped: %+v", got.Client.Endpoints)
	}
	if got.Client.Legacy.SharedSecret.File != "/run/secrets/lab_switches_tacacs_secret" {
		t.Fatalf("TACACS secret dropped: %+v", got.Client.Legacy.SharedSecret)
	}
}

func TestOverlayTACACSPatchRetainsRADIUSSecret(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	rev := m.Revision()
	snap, err := m.UpdateClient("lab-switches", UpdateClient{
		SharedSecret: &SecretPatch{Ref: config.SecretRef{
			Purpose: credentials.PurposeLegacySharedSecret,
			File:    "/run/secrets/lab_switches_tacacs_secret_v2",
		}},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := snap.Client("lab-switches")
	if got.Client.Legacy.SharedSecret.File != "/run/secrets/lab_switches_tacacs_secret_v2" {
		t.Fatalf("TACACS secret=%+v", got.Client.Legacy.SharedSecret)
	}
	if radiusSecretFile(got.Client) != "/run/secrets/lab_switches_radius_secret" {
		t.Fatalf("RADIUS secret not retained: %q", radiusSecretFile(got.Client))
	}
	// Projection must still hold on the effective client (mixed RADIUS).
	synth := mustParse(t, mixedRADIUSYAML)
	synth.Clients[0] = got.Client
	if err := config.Validate(synth); err != nil {
		t.Fatalf("projection after TACACS secret patch: %v", err)
	}
}

func TestNullRADIUSSecretRejected(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, mixedRADIUSYAML)
	before := m.Snapshot()
	rev := before.Revision
	_, err := m.UpdateClient("lab-switches", UpdateClient{RADIUSSharedSecret: &SecretPatch{Clear: true}}, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeRADIUSSecretMissing {
		t.Fatalf("got %v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("null RADIUS secret must not publish")
	}
	got, _ := m.Snapshot().Client("lab-switches")
	if radiusSecretFile(got.Client) != "/run/secrets/lab_switches_radius_secret" {
		t.Fatal("RADIUS secret must remain")
	}
}

func TestNewRejectsAmbiguousRADIUS(t *testing.T) {
	t.Parallel()
	_, err := New(mustParse(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
clients:
  - id: a
    priority: 1
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r1
        protocol: radius
        transport: udp
        roles: [access]
        radius: {shared_secret: {file: /run/secrets/a}}
  - id: b
    priority: 1
    match:
      source_cidrs: ["192.0.2.0/24"]
    endpoints:
      - id: r2
        protocol: radius
        transport: udp
        roles: [access]
        radius: {shared_secret: {file: /run/secrets/b}}
`), Options{})
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeClientMatchAmbiguous {
		t.Fatalf("got %v", err)
	}
}

func mustParseFile(t *testing.T, path string) *config.Document {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, string(b))
}

func assertRADIUSIndexEmpty(t *testing.T, s *Snapshot) {
	t.Helper()
	_, _, err := s.MatchRADIUS(domain.RoleAccess, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err == nil {
		t.Fatal("expected empty access index")
	}
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("access empty: %v", err)
	}
	_, _, err = s.MatchRADIUS(domain.RoleAccounting, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err == nil {
		t.Fatal("expected empty accounting index")
	}
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("acct empty: %v", err)
	}
	_, _, err = s.MatchRADIUS(domain.RoleDynamicAuthorization, domain.CarrierRADIUSUDP, net.ParseIP("192.0.2.10"))
	if err == nil {
		t.Fatal("expected empty dynauth index")
	}
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("dynauth empty: %v", err)
	}
}

func radiusSecretFile(c config.Client) string {
	for _, ep := range c.Endpoints {
		if ep.Protocol == domain.ProtocolRADIUS && ep.RADIUS != nil {
			return ep.RADIUS.SharedSecret.File
		}
	}
	return ""
}

func tacacsUsers(s *Snapshot) []config.User {
	out := make([]config.User, 0, len(s.Users()))
	for _, u := range s.Users() {
		out = append(out, u.User)
	}
	return out
}

func tacacsGroups(s *Snapshot) []config.Group {
	out := make([]config.Group, 0, len(s.Groups()))
	for _, g := range s.Groups() {
		out = append(out, g.Group)
	}
	return out
}

type tacacsClientView struct {
	ID             string
	DisplayName    string
	Priority       int
	Enabled        bool
	Match          config.ClientMatch
	Legacy         config.ClientLegacy
	Authentication config.ClientAuth
	Authorization  config.ClientAuthz
	Accounting     config.ClientAcct
}

func tacacsClients(s *Snapshot) []tacacsClientView {
	out := make([]tacacsClientView, 0, len(s.Clients()))
	for _, c := range s.Clients() {
		out = append(out, tacacsClientView{
			ID:             c.Client.ID,
			DisplayName:    c.Client.DisplayName,
			Priority:       c.Client.Priority,
			Enabled:        c.Client.Enabled,
			Match:          c.Client.Match,
			Legacy:         c.Client.Legacy,
			Authentication: c.Client.Authentication,
			Authorization:  c.Client.Authorization,
			Accounting:     c.Client.Accounting,
		})
	}
	return out
}

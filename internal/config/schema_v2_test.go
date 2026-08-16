package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestParseV2MinimalDefaults(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_minimal.yaml")
	if doc.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("schema=%d", doc.SchemaVersion)
	}
	if doc.Server.AdminOnly {
		t.Fatal("admin_only must default false")
	}
	if doc.Security.RADIUSSharedSecrets != doc.Security.LegacySharedSecrets {
		t.Fatalf("radius secret policy must copy legacy defaults: %+v vs %+v", doc.Security.RADIUSSharedSecrets, doc.Security.LegacySharedSecrets)
	}
	assertRADIUSDisabledDefaults(t, doc)
	if !doc.Listeners.LegacyTACACS.Enabled || !doc.Listeners.SecureTACACS.Enabled {
		t.Fatal("omitted TACACS listeners keep v1 defaults (enabled)")
	}
}

func TestParseV2RADIUSDefaults(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_defaults.yaml")
	assertRADIUSDisabledDefaults(t, doc)
	if doc.Listeners.RADIUSAccess.MaxPacketBytes == 4095 {
		t.Fatal("max_packet_bytes must default to 4096, not 4095")
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
}

func TestV1AndV2TACACSEquivalent(t *testing.T) {
	t.Parallel()
	v1 := mustParseFile(t, "testdata/parse/v1_tacacs_equivalent.yaml")
	v2 := mustParseFile(t, "testdata/parse/v2_tacacs_equivalent.yaml")
	if v1.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("v1 schema=%d", v1.SchemaVersion)
	}
	if v2.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("v2 schema=%d", v2.SchemaVersion)
	}
	if err := Validate(v1); err != nil {
		t.Fatalf("validate v1: %v", err)
	}
	if err := ValidateV2(v2); err != nil {
		t.Fatalf("validate v2: %v", err)
	}
	a, b := *v1, *v2
	a.SchemaVersion = 0
	b.SchemaVersion = 0
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("migrated v1 and hand-written v2 differ\n v1=%+v\n v2=%+v", a, b)
	}
}

func TestV1FixturesKeepTACACSAndDisableRADIUS(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("testdata/parse")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "v2_") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doc := mustParseFile(t, filepath.Join("testdata/parse", name))
			if doc.SchemaVersion != SchemaVersionV1 {
				t.Fatalf("schema=%d", doc.SchemaVersion)
			}
			assertRADIUSDisabledDefaults(t, doc)
			if doc.Server.AdminOnly {
				t.Fatal("v1 must not enable admin_only")
			}
		})
	}
}

func TestV2AcceptsEnabledRADIUSListeners(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access:
      enabled: true
      required: true
      bind: 0.0.0.0:1812
      retransmission_cache_bytes: 4MiB
    accounting:
      enabled: true
      bind: 0.0.0.0:1813
      journal_bytes: 8MiB
      retransmission_cache_bytes: 8MiB
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Listeners.RADIUSAccess.Enabled || !doc.Listeners.RADIUSAccess.Required {
		t.Fatalf("access=%+v", doc.Listeners.RADIUSAccess)
	}
	if !doc.Listeners.RADIUSAccounting.Enabled {
		t.Fatal("accounting should be enabled")
	}
	if doc.Listeners.RADIUSAccess.RetransmissionCacheBytes != 4<<20 {
		t.Fatalf("access cache bytes=%d", doc.Listeners.RADIUSAccess.RetransmissionCacheBytes)
	}
	if doc.Listeners.RADIUSAccounting.JournalBytes != 8<<20 {
		t.Fatalf("journal bytes=%d", doc.Listeners.RADIUSAccounting.JournalBytes)
	}
	if err := ValidateV2(doc); err != nil {
		t.Fatal(err)
	}
}

func TestV2AdminOnlyAndRADIUSSecretPolicy(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
server:
  admin_only: true
security:
  legacy_shared_secrets:
    minimum_length_characters: 24
  radius_shared_secrets:
    minimum_length_characters: 32
listeners:
  tacacs:
    tls: {enabled: false}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Server.AdminOnly {
		t.Fatal("admin_only")
	}
	if doc.Security.LegacySharedSecrets.MinimumLengthCharacters != 24 {
		t.Fatalf("legacy=%d", doc.Security.LegacySharedSecrets.MinimumLengthCharacters)
	}
	if doc.Security.RADIUSSharedSecrets.MinimumLengthCharacters != 32 {
		t.Fatalf("radius=%d", doc.Security.RADIUSSharedSecrets.MinimumLengthCharacters)
	}
	if doc.Security.RADIUSSharedSecrets.MinimumCharacterClasses != 3 {
		t.Fatal("radius policy remainder must copy legacy defaults")
	}
}

func TestV2ParsesRadiusPolicies(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_policies.yaml")
	if len(doc.RADIUSPolicies) != 1 || doc.RADIUSPolicies[0].ID != "default-radius-access" {
		t.Fatalf("policies=%+v", doc.RADIUSPolicies)
	}
	rule := doc.RADIUSPolicies[0].Rules[0]
	if rule.Match.Method == nil || *rule.Match.Method != domain.AuthMethodPassword {
		t.Fatalf("pap alias must store password: %#v", rule.Match.Method)
	}
	if doc.FallbackRADIUSPolicyID != "default-radius-access" {
		t.Fatalf("fallback=%q", doc.FallbackRADIUSPolicyID)
	}
	if len(doc.RADIUSReplyProfiles) != 1 || doc.RADIUSReplyProfiles[0].Attributes[0].Name != "Session-Timeout" {
		t.Fatalf("profiles=%+v", doc.RADIUSReplyProfiles)
	}
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestV2ParsesUserAndGroupRADIUSPolicyID(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_user_group_radius_policy.yaml")
	if len(doc.Users) != 1 || doc.Users[0].RADIUSPolicyID != "admin-radius" {
		t.Fatalf("users=%+v", doc.Users)
	}
	if len(doc.Groups) != 1 || doc.Groups[0].RADIUSPolicyID != "admins-radius" {
		t.Fatalf("groups=%+v", doc.Groups)
	}
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestV2ParsesRadiusDictionaries(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_radius_dictionaries.yaml")
	if len(doc.RADIUSDictionaries) != 2 {
		t.Fatalf("dicts=%+v", doc.RADIUSDictionaries)
	}
	if doc.RADIUSDictionaries[0].ID != "lab-juniper" || doc.RADIUSDictionaries[0].File != "/etc/taclab/dicts/juniper.yaml" || !doc.RADIUSDictionaries[0].Enabled {
		t.Fatalf("first=%+v", doc.RADIUSDictionaries[0])
	}
	if doc.RADIUSDictionaries[1].ID != "lab-disabled" || doc.RADIUSDictionaries[1].Enabled {
		t.Fatalf("disabled=%+v", doc.RADIUSDictionaries[1])
	}
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestV2RejectsUnknownUserRADIUSPolicyID(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
users:
  - id: lab-admin
    radius_policy_id: missing
    credentials:
      login:
        verifier: {file: /run/secrets/lab-admin-login}
`)
	if err == nil {
		t.Fatal("expected missing user radius_policy_id")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "radius_policy_id") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestV2RejectsUnknownGroupRADIUSPolicyID(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
groups:
  - id: lab-admins
    radius_policy_id: missing
`)
	if err == nil {
		t.Fatal("expected missing group radius_policy_id")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "radius_policy_id") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestV2RejectsUnknownUserRADIUSPolicyField(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte(`
schema_version: 2
users:
  - id: lab-admin
    radius_rules: []
`))
	if err == nil {
		t.Fatal("expected unknown field")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigUnknownField {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "radius_rules") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestCompileRADIUSDictionaryEmptyStaysBuiltin(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/v2_minimal.yaml")
	d, err := CompileRADIUSDictionary(doc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() != "builtin-mvp-1" {
		t.Fatalf("version=%q", d.Version())
	}
}

func TestV2RadiusDictionariesTooMany(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("schema_version: 2\nlisteners:\n  tacacs:\n    tls: {enabled: false}\nradius_dictionaries:\n")
	for i := 0; i < 9; i++ {
		b.WriteString("  - {id: d")
		b.WriteString(strings.Repeat("x", 0))
		b.WriteString(itoa(i))
		b.WriteString(", file: /etc/taclab/dicts/d")
		b.WriteString(itoa(i))
		b.WriteString(".yaml}\n")
	}
	_, err := Parse([]byte(b.String()))
	if err == nil {
		t.Fatal("expected error")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("err=%v", err)
	}
}

func TestV1RejectsAdminOnly(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("schema_version: 1\nserver:\n  admin_only: true\n"))
	if err == nil || !strings.Contains(err.Error(), "admin_only") {
		t.Fatalf("%v", err)
	}
}

func TestParseByteSize(t *testing.T) {
	t.Parallel()
	n, err := parseByteSize("4MiB", "x")
	if err != nil || n != 4<<20 {
		t.Fatalf("4MiB -> %d %v", n, err)
	}
	n, err = parseByteSize("4096", "x")
	if err != nil || n != 4096 {
		t.Fatalf("4096 -> %d %v", n, err)
	}
	if _, err := parseByteSize("nope", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestV2AccessTTLBounds(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access:
      retransmission_ttl: 4s
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateV2(doc)
	if err == nil || !strings.Contains(err.Error(), "retransmission_ttl") {
		t.Fatalf("got %v", err)
	}
}

func TestV2ChallengeKnobBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"ttl", "challenge_ttl: 4s", "challenge_ttl"},
		{"ttl-high", "challenge_ttl: 61s", "challenge_ttl"},
		{"entries", "challenge_entries: 8", "challenge_entries"},
		{"bytes", "challenge_bytes: 1024", "challenge_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    access:
      ` + tc.yaml + `
`)
			doc, err := Parse(src)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateV2(doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %s", err, tc.want)
			}
		})
	}
}

func TestV2AccountingRejectsChallengeKeys(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
  radius:
    accounting:
      challenge_ttl: 30s
`)
	if _, err := Parse(src); err == nil {
		t.Fatal("accounting challenge_ttl must be unknown")
	}
}

func assertRADIUSDisabledDefaults(t *testing.T, doc *Document) {
	t.Helper()
	acc := doc.Listeners.RADIUSAccess
	acct := doc.Listeners.RADIUSAccounting
	if acc.Enabled || acct.Enabled {
		t.Fatalf("RADIUS listeners must default disabled: access=%v acct=%v", acc.Enabled, acct.Enabled)
	}
	if acc.Required || acct.Required {
		t.Fatal("RADIUS required must default false")
	}
	if acc.MaxPacketBytes != RADIUSMaxPacketBytes || acct.MaxPacketBytes != RADIUSMaxPacketBytes {
		t.Fatalf("max_packet_bytes access=%d acct=%d want %d", acc.MaxPacketBytes, acct.MaxPacketBytes, RADIUSMaxPacketBytes)
	}
	if acc.MaxPacketBytes == 4095 || acct.MaxPacketBytes == 4095 {
		t.Fatal("max_packet_bytes must not be 4095")
	}
	if acc.Bind != "0.0.0.0:1812" || acct.Bind != "0.0.0.0:1813" {
		t.Fatalf("binds access=%q acct=%q", acc.Bind, acct.Bind)
	}
	if acc.Transport != RADIUSTransportUDP || acct.Transport != RADIUSTransportUDP {
		t.Fatalf("transport access=%q acct=%q", acc.Transport, acct.Transport)
	}
	if acc.QueueCapacity != 2048 || acct.QueueCapacity != 2048 {
		t.Fatalf("queue access=%d acct=%d", acc.QueueCapacity, acct.QueueCapacity)
	}
	if acc.Workers != 32 || acct.Workers != 16 {
		t.Fatalf("workers access=%d acct=%d", acc.Workers, acct.Workers)
	}
	if acc.WorkerDeadline != 5*time.Second || acct.WorkerDeadline != 5*time.Second {
		t.Fatalf("deadline access=%s acct=%s", acc.WorkerDeadline, acct.WorkerDeadline)
	}
	if acc.RetransmissionCacheEntries != 10000 || acct.RetransmissionCacheEntries != 20000 {
		t.Fatalf("cache entries access=%d acct=%d", acc.RetransmissionCacheEntries, acct.RetransmissionCacheEntries)
	}
	if acc.RetransmissionCacheBytes != 4<<20 || acct.RetransmissionCacheBytes != 8<<20 {
		t.Fatalf("cache bytes access=%d acct=%d", acc.RetransmissionCacheBytes, acct.RetransmissionCacheBytes)
	}
	if acc.RetransmissionTTL != 15*time.Second || acct.RetransmissionTTL != 60*time.Second {
		t.Fatalf("ttl access=%s acct=%s", acc.RetransmissionTTL, acct.RetransmissionTTL)
	}
	if acc.PerSourceRate != 100 || acc.PerSourceBurst != 200 {
		t.Fatalf("access rate=%v burst=%d", acc.PerSourceRate, acc.PerSourceBurst)
	}
	if acct.PerSourceRate != 100 || acct.PerSourceBurst != 200 {
		t.Fatalf("acct rate=%v burst=%d", acct.PerSourceRate, acct.PerSourceBurst)
	}
	if acc.MessageAuthenticator != RADIUSMessageAuthenticatorRequired || !acc.LimitProxyState {
		t.Fatalf("access MA=%q limit_proxy=%v", acc.MessageAuthenticator, acc.LimitProxyState)
	}
	if acct.JournalEntries != 20000 || acct.JournalBytes != 8<<20 || acct.AmbiguousAccountingPerMinute != 60 {
		t.Fatalf("journal entries=%d bytes=%d ambig=%d", acct.JournalEntries, acct.JournalBytes, acct.AmbiguousAccountingPerMinute)
	}
	if acc.ChallengeTTL != RADIUSChallengeTTLDefault || acc.ChallengeEntries != RADIUSChallengeEntriesDefault || acc.ChallengeBytes != RADIUSChallengeBytesDefault {
		t.Fatalf("challenge ttl=%s entries=%d bytes=%d", acc.ChallengeTTL, acc.ChallengeEntries, acc.ChallengeBytes)
	}
	if acct.ChallengeTTL != 0 || acct.ChallengeEntries != 0 || acct.ChallengeBytes != 0 {
		t.Fatalf("accounting must ignore challenge knobs: ttl=%s entries=%d bytes=%d", acct.ChallengeTTL, acct.ChallengeEntries, acct.ChallengeBytes)
	}
	if acct.SessionIndexEntries != DefaultSessionIndexEntries || acct.SessionIndexBytes != DefaultSessionIndexBytes || acct.SessionTTL != DefaultSessionTTL || acct.CoATimeout != DefaultCoATimeout {
		t.Fatalf("session index entries=%d bytes=%d ttl=%s coa_timeout=%s", acct.SessionIndexEntries, acct.SessionIndexBytes, acct.SessionTTL, acct.CoATimeout)
	}
}

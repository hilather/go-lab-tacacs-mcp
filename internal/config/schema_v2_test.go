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

func TestV2RejectsClientEndpoints(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 2
clients:
  - id: sw
    endpoints:
      - id: radius-udp
        protocol: radius
`)
	_, err := Parse(src)
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
}

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func parseAndValidate(t *testing.T, src string) (*Document, error) {
	t.Helper()
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc, Validate(doc)
}

func TestScopesExactSet(t *testing.T) {
	t.Parallel()
	got := Scopes()
	if len(got) != len(knownScopes) {
		t.Fatalf("len=%d map=%d", len(got), len(knownScopes))
	}
	for _, s := range got {
		if !ValidScope(s) {
			t.Fatalf("invalid listed scope %q", s)
		}
	}
	if ValidScope("admin") {
		t.Fatal("unknown scope accepted")
	}
}

func TestValidateLabExample(t *testing.T) {
	t.Parallel()
	doc, err := Load(filepath.Join("..", "..", "configs", "lab.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGroupNotFound(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
users:
  - id: alice
    group_ids: [missing]
`)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeGroupNotFound {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(de.Path, "group_ids") {
		t.Fatalf("path=%q", de.Path)
	}
}

func TestValidateClientDefaultGroupNotFound(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: c
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/x}
    authorization:
      default_group_ids: [nope]
`)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeGroupNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestValidateLegacySecretRequired(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: c
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
`)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeAuthMethodCredentialMissing {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRegexInvalid(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
groups:
  - id: g
    command_rules:
      - id: bad
        action: deny
        command: {pattern: "(unclosed"}
        arguments: {pattern: ".*"}
`)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeRegexInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestValidateDuplicateCommandPriority(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
groups:
  - id: g
    command_rules:
      - id: a
        priority: 10
        action: deny
        command: {exact: a}
        arguments: {pattern: ".*"}
      - id: b
        priority: 10
        action: deny
        command: {exact: b}
        arguments: {pattern: ".*"}
`)
	if err == nil || !strings.Contains(err.Error(), "duplicate command rule priority") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateObjectLimit(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
runtime:
  max_objects:
    users: 1
users:
  - id: a
  - id: b
`)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeObjectLimitExceeded {
		t.Fatalf("got %v", err)
	}
}

func TestValidateUnknownScope(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
api:
  bootstrap_tokens:
    - id: t
      token: {file: /run/secrets/t}
      scopes: [not-a-scope]
`)
	if err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateSecureTLSRequiresIdentity(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
`)
	if err == nil {
		t.Fatal("default-enabled secure listener without identities must fail")
	}
}

func TestValidateRejectsUnenforceableTicketLifetime(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs:
    enabled: true
    tls:
      identities:
        profiles:
          - id: p
            server_names: [tacacs.lab.example]
            certificate_chain: {file: /tmp/chain.pem}
            private_key: {file: /tmp/key.pem}
      client_ca_bundle: {file: /tmp/ca.pem}
      revocation: {mode: configured_crl, crl_bundle: {file: /tmp/crl.pem}}
      session_resumption: {enabled: true, ticket_lifetime: 24h}
`)
	if err == nil || !strings.Contains(err.Error(), "ticket_lifetime") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsRevocationRecheckDisabled(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs:
    enabled: true
    tls:
      identities:
        profiles:
          - id: p
            server_names: [tacacs.lab.example]
            certificate_chain: {file: /tmp/chain.pem}
            private_key: {file: /tmp/key.pem}
      client_ca_bundle: {file: /tmp/ca.pem}
      revocation: {mode: configured_crl, crl_bundle: {file: /tmp/crl.pem}}
      session_resumption: {enabled: true, ticket_lifetime: 168h, recheck_client_revocation: false}
`)
	if err == nil || !strings.Contains(err.Error(), "recheck_client_revocation") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsEarlyDataDisabled(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs:
    enabled: true
    tls:
      identities:
        profiles:
          - id: p
            server_names: [tacacs.lab.example]
            certificate_chain: {file: /tmp/chain.pem}
            private_key: {file: /tmp/key.pem}
      client_ca_bundle: {file: /tmp/ca.pem}
      revocation: {mode: configured_crl, crl_bundle: {file: /tmp/crl.pem}}
      reject_early_data: false
`)
	if err == nil || !strings.Contains(err.Error(), "reject_early_data") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsNonTACACSWildcard(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs:
    enabled: true
    tls:
      identities:
        profiles:
          - id: p
            server_names: ["*.lab.example"]
            certificate_chain: {file: /tmp/chain.pem}
            private_key: {file: /tmp/key.pem}
      client_ca_bundle: {file: /tmp/ca.pem}
      revocation: {mode: configured_crl, crl_bundle: {file: /tmp/crl.pem}}
`)
	if err == nil || !strings.Contains(err.Error(), "tacacs") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsInvalidIPSAN(t *testing.T) {
	t.Parallel()
	doc, err := Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: c
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [tls]
`))
	if err != nil {
		t.Fatal(err)
	}
	doc.Clients[0].Match.Certificate.IPSANs = []string{"not-an-ip"}
	err = Validate(doc)
	if err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRestrictedClientMissing(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
users:
  - id: alice
    restrictions:
      client_ids: [ghost]
`)
	if err == nil || !strings.Contains(err.Error(), "restricted client") {
		t.Fatalf("got %v", err)
	}
}

func TestEvaluateSecretsReuseAndLifecycle(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	rotated := now.Add(-100 * 24 * time.Hour)
	doc, err := Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
security:
  legacy_shared_secrets:
    warn_on_reuse: true
    reject_known_weak_values: true
    minimum_length_characters: 16
    minimum_character_classes: 3
clients:
  - id: a
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/a}
      shared_secret_lifecycle:
        last_rotated_at: 2026-01-01T00:00:00Z
        rotation_interval: 90d
  - id: b
    match:
      source_cidrs: ["11.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/b}
`))
	if err != nil {
		t.Fatal(err)
	}
	doc.Clients[0].Legacy.SharedSecretLifecycle.LastRotatedAt = &rotated
	good := []byte("Str0ng-Shared-Secret!!")
	lookup := func(ref SecretRef) ([]byte, error) {
		cp := make([]byte, len(good))
		copy(cp, good)
		return cp, nil
	}
	life, warns, err := EvaluateSecrets(doc, lookup, now, []byte("process-local-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	if life["a"] != domain.LifecycleOverdue {
		t.Fatalf("lifecycle a=%s", life["a"])
	}
	if life["b"] != domain.LifecycleUnknown && life["b"] != domain.LifecycleOverdue && life["b"] != domain.LifecycleCurrent && life["b"] != domain.LifecycleDueSoon {
		t.Fatalf("lifecycle b=%s", life["b"])
	}
	var reuse, overdue bool
	for _, w := range warns {
		if w.Code == domain.CodeSharedSecretPolicyViolation {
			reuse = true
			if !strings.Contains(w.Message, "clients a, b") {
				t.Fatalf("reuse warning must name client ids: %+v", w)
			}
			if strings.Contains(w.Message, string(good)) || strings.Contains(w.Path, string(good)) {
				t.Fatalf("warning leaked secret: %+v", w)
			}
		}
		if w.Code == domain.CodeSharedSecretRotationOverdue {
			overdue = true
		}
	}
	if !reuse {
		t.Fatal("expected reuse warning")
	}
	if !overdue {
		t.Fatal("expected overdue warning")
	}
}

func TestEvaluateSecretsRejectsWeakWithoutEcho(t *testing.T) {
	t.Parallel()
	doc, err := Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: a
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/a}
`))
	if err != nil {
		t.Fatal(err)
	}
	weak := []byte("password")
	lookup := func(SecretRef) ([]byte, error) {
		cp := make([]byte, len(weak))
		copy(cp, weak)
		return cp, nil
	}
	_, _, err = EvaluateSecrets(doc, lookup, time.Now().UTC(), nil)
	if err == nil {
		t.Fatal("expected policy violation")
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("echoed secret: %v", err)
	}
}

func TestEvaluateSecretsOmitsTLSOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	rotated := now.Add(-10 * 24 * time.Hour)
	doc, err := Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
security:
  legacy_shared_secrets:
    minimum_character_classes: 0
    reject_known_weak_values: false
    minimum_length_characters: 8
clients:
  - id: legacy
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/legacy}
      shared_secret_lifecycle:
        last_rotated_at: 2026-08-02T00:00:00Z
        rotation_interval: 90d
  - id: tls-only
    match:
      source_cidrs: ["10.1.0.0/16"]
      transports: [tls]
`))
	if err != nil {
		t.Fatal(err)
	}
	doc.Clients[0].Legacy.SharedSecretLifecycle.LastRotatedAt = &rotated
	good := []byte("Str0ng-Shared-Secret!!")
	lookup := func(SecretRef) ([]byte, error) {
		cp := make([]byte, len(good))
		copy(cp, good)
		return cp, nil
	}
	life, warns, err := EvaluateSecrets(doc, lookup, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := life["tls-only"]; ok {
		t.Fatalf("TLS-only client must be omitted from lifecycle map: %+v", life)
	}
	if life["legacy"] != domain.LifecycleCurrent {
		t.Fatalf("legacy=%s", life["legacy"])
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %+v", warns)
	}
}

func TestEvaluateSecretsRADIUSPurposeAndCrossReuse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	tacacsPath := writeSecret(t, dir, "tacacs", "Str0ng-Shared-Secret!!\n", 0o600)
	radiusPath := writeSecret(t, dir, "radius", "Str0ng-Shared-Secret!!\n", 0o600)
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
security:
  legacy_shared_secrets:
    warn_on_reuse: true
    reject_known_weak_values: true
    minimum_length_characters: 16
    minimum_character_classes: 3
  radius_shared_secrets:
    warn_on_reuse: true
    reject_known_weak_values: true
    minimum_length_characters: 16
    minimum_character_classes: 3
clients:
  - id: tacacs
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: ` + tacacsPath + `}
  - id: radius
    match:
      source_cidrs: ["11.0.0.0/8"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: ` + radiusPath + `}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	// Resolve through ReadSecret so purpose mapping is covered, then EvaluateSecrets.
	_, holder, err := ReadSecret(doc.Clients[1].Endpoints[0].RADIUS.SharedSecret, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := holder.(credentials.RADIUSSharedSecret); !ok {
		t.Fatalf("ReadSecret type=%T", holder)
	}
	life, warns, err := EvaluateSecrets(doc, FileLookup(ReadOptions{}), now, []byte("process-local-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := life["tacacs"]; !ok {
		t.Fatalf("missing tacacs lifecycle: %+v", life)
	}
	if _, ok := life["radius/radius-udp"]; !ok {
		t.Fatalf("missing radius lifecycle: %+v", life)
	}
	var reuse bool
	for _, w := range warns {
		if w.Code == domain.CodeSharedSecretPolicyViolation {
			reuse = true
			if strings.Contains(w.Message, "Str0ng-Shared-Secret!!") {
				t.Fatalf("warning leaked secret: %+v", w)
			}
			if !strings.Contains(w.Message, "tacacs") || !strings.Contains(w.Message, "radius") {
				t.Fatalf("reuse must name both clients: %+v", w)
			}
		}
	}
	if !reuse {
		t.Fatal("expected cross-purpose reuse warning")
	}
}

func TestValidateRADIUSPolicyRefs(t *testing.T) {
	t.Parallel()
	_, err := parseAndValidate(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
fallback_radius_policy_id: missing
`)
	if err == nil {
		t.Fatal("missing fallback")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeNotFound {
		t.Fatalf("got %v", err)
	}
	_, err = parseAndValidate(t, `
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
radius_policies:
  - id: p
    rules:
      - id: r
        match:
          groups_any: [no-such-group]
        effect: deny
`)
	if err == nil {
		t.Fatal("unknown group")
	}
	de, ok = domain.AsError(err)
	if !ok || de.Code != domain.CodeGroupNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestEvaluateSecretsRADIUSPolicyRejectsWithoutEcho(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := writeSecret(t, dir, "r", "password\n", 0o600)
	src := []byte(`
schema_version: 2
listeners:
  tacacs:
    tls: {enabled: false}
security:
  radius_shared_secrets:
    reject_known_weak_values: true
    minimum_length_characters: 8
clients:
  - id: radius
    match:
      source_cidrs: ["10.0.0.0/8"]
    endpoints:
      - id: radius-udp
        protocol: radius
        transport: udp
        roles: [access]
        radius:
          shared_secret: {file: ` + p + `}
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = EvaluateSecrets(doc, FileLookup(ReadOptions{}), time.Now().UTC(), nil)
	if err == nil {
		t.Fatal("expected policy violation")
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("echoed secret: %v", err)
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeSharedSecretPolicyViolation {
		t.Fatalf("got %v", err)
	}
}

func TestSecretLifecycleDueSoonAndCurrent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	policy := SharedSecretPolicy{
		DefaultRotationInterval: 90 * 24 * time.Hour,
		RotationWarningBefore:   14 * 24 * time.Hour,
	}
	current := now.Add(-10 * 24 * time.Hour)
	dueSoon := now.Add(-80 * 24 * time.Hour)
	if got := SecretLifecycleStatus(SecretLifecycleMeta{LastRotatedAt: &current, RotationInterval: 90 * 24 * time.Hour}, policy, now); got != domain.LifecycleCurrent {
		t.Fatalf("current=%s", got)
	}
	if got := SecretLifecycleStatus(SecretLifecycleMeta{LastRotatedAt: &dueSoon, RotationInterval: 90 * 24 * time.Hour}, policy, now); got != domain.LifecycleDueSoon {
		t.Fatalf("due_soon=%s", got)
	}
	if got := SecretLifecycleStatus(SecretLifecycleMeta{}, policy, now); got != domain.LifecycleUnknown {
		t.Fatalf("unknown=%s", got)
	}
}

func TestValidateDoesNotReadSecretFiles(t *testing.T) {
	t.Parallel()
	doc, err := Parse([]byte(`
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: c
    match:
      source_cidrs: ["10.0.0.0/8"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /no/such/secret-file}
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/no/such/secret-file"); err == nil {
		t.Fatal("fixture path exists")
	}
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

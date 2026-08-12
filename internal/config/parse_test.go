package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func mustParseFile(t *testing.T, rel string) *Document {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(%s): %v", rel, err)
	}
	return doc
}

func TestParseMinimalDefaults(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/minimal.yaml")
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("schema=%d", doc.SchemaVersion)
	}
	if doc.Runtime.Persistence != "memory" || !doc.Runtime.AllowShadowing {
		t.Fatalf("runtime defaults: %+v", doc.Runtime)
	}
	if doc.Security.AllowEnvironmentSecrets {
		t.Fatal("environment secrets must default off")
	}
	if !doc.Security.StrictSecretFiles {
		t.Fatal("strict secret files must default on")
	}
	if doc.API.MCP.RequireOrigin {
		t.Fatal("require_origin must default false")
	}
	if doc.API.MCP.AllowedOrigins == nil || len(doc.API.MCP.AllowedOrigins) != 0 {
		t.Fatalf("allowed_origins default=%v", doc.API.MCP.AllowedOrigins)
	}
	if doc.API.UISession.CookieSecure {
		t.Fatal("cookie_secure must follow HTTP TLS off")
	}
	if doc.Listeners.HTTP.TLS.Enabled {
		t.Fatal("http tls default")
	}
	if doc.Security.LegacySharedSecrets.MinimumLengthCharacters != 16 {
		t.Fatalf("min length=%d", doc.Security.LegacySharedSecrets.MinimumLengthCharacters)
	}
	if doc.Security.LegacySharedSecrets.DefaultRotationInterval != 90*24*time.Hour {
		t.Fatalf("rotation=%s", doc.Security.LegacySharedSecrets.DefaultRotationInterval)
	}
}

func TestParseMCPOrigins(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/mcp_origins.yaml")
	if doc.API.MCP.RequireOrigin != true {
		t.Fatal("require_origin")
	}
	if len(doc.API.MCP.AllowedOrigins) != 2 || doc.API.MCP.AllowedOrigins[0] != "https://lab.example" {
		t.Fatalf("origins=%v", doc.API.MCP.AllowedOrigins)
	}
}

func TestParsePermitAliasAndUserRules(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/permit_alias.yaml")
	if doc.Groups[0].Services[0].Action != domain.DecisionPermitAdd {
		t.Fatalf("yaml permit alias=%q", doc.Groups[0].Services[0].Action)
	}
	if doc.Groups[0].CommandRules[0].Action != domain.DecisionPermitReplace {
		t.Fatalf("permit_replace=%q", doc.Groups[0].CommandRules[0].Action)
	}
	if doc.Groups[0].DefaultCommandAction != domain.DecisionDeny {
		t.Fatal("default command action")
	}
	if len(doc.Users[0].Rules.Services) != 1 || doc.Users[0].Rules.Services[0].Action != domain.DecisionPermitAdd {
		t.Fatalf("user rules=%+v", doc.Users[0].Rules)
	}
	if len(doc.Users[0].Rules.CommandRules) != 1 || doc.Users[0].Rules.CommandRules[0].Action != domain.DecisionDeny {
		t.Fatal("user command rules")
	}
	if _, err := domain.ParseAuthorDecision("permit"); err == nil {
		t.Fatal("domain must still reject bare permit")
	}
}

func TestParseCookieSecureFollowsTLS(t *testing.T) {
	t.Parallel()
	doc := mustParseFile(t, "testdata/parse/cookie_follow_tls.yaml")
	if !doc.Listeners.HTTP.TLS.Enabled {
		t.Fatal("tls")
	}
	if !doc.API.UISession.CookieSecure {
		t.Fatal("cookie_secure should follow TLS")
	}
}

func TestParseLabExample(t *testing.T) {
	t.Parallel()
	doc, err := Load(filepath.Join("..", "..", "configs", "lab.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != "branch-routing-lab" {
		t.Fatalf("name=%q", doc.Metadata.Name)
	}
	if len(doc.API.MCP.AllowedOrigins) != 0 || doc.API.MCP.RequireOrigin {
		t.Fatalf("mcp=%+v", doc.API.MCP)
	}
	if doc.API.UISession.CookieSecure {
		t.Fatal("example cookie_secure is false for HTTP lab")
	}
	var disabled *User
	for i := range doc.Users {
		if doc.Users[i].ID == "lab-disabled" {
			disabled = &doc.Users[i]
		}
	}
	if disabled == nil || disabled.Enabled {
		t.Fatal("lab-disabled persona missing or enabled")
	}
	if doc.Groups[0].Services[0].Action != domain.DecisionPermitAdd {
		t.Fatal("example permit alias")
	}
	if doc.Clients[0].Legacy.SharedSecret.Purpose != credentials.PurposeLegacySharedSecret {
		t.Fatal("typed shared secret purpose")
	}
	if doc.Clients[0].Legacy.SharedSecret.File == "" {
		t.Fatal("shared secret file ref")
	}
	if doc.Clients[0].Match.Mode != domain.MatchAddressAndCertificate {
		t.Fatal("match mode")
	}
	if len(doc.Clients[0].Match.SourceCIDRs) != 2 {
		t.Fatalf("dual-stack cidrs=%v", doc.Clients[0].Match.SourceCIDRs)
	}
	if doc.Users[0].Credentials.Login.Verifier.Purpose != credentials.PurposeLoginVerifier {
		t.Fatal("login verifier purpose")
	}
	if doc.FallbackRules.Services != nil && len(doc.FallbackRules.Services) != 0 {
		t.Fatalf("fallback=%+v", doc.FallbackRules)
	}
}

func TestRejectFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file string
		code domain.Code
		path string
		msg  string
	}{
		{"testdata/reject/unknown_field.yaml", domain.CodeConfigUnknownField, "clients[0].authentcation", "authentication"},
		{"testdata/reject/cipher_suites.yaml", domain.CodeConfigUnknownField, "cipher_suites", "cipher"},
		{"testdata/reject/duplicate_key.yaml", domain.CodeConfigYAMLInvalid, "metadata.name", "duplicate"},
		{"testdata/reject/alias.yaml", domain.CodeConfigYAMLInvalid, "", "not allowed"},
		{"testdata/reject/anchor.yaml", domain.CodeConfigYAMLInvalid, "", "anchor"},
		{"testdata/reject/merge_key.yaml", domain.CodeConfigYAMLInvalid, "", "merge"},
		{"testdata/reject/multi_document.yaml", domain.CodeConfigYAMLInvalid, "", "multiple"},
		{"testdata/reject/missing_schema.yaml", domain.CodeConfigYAMLInvalid, "schema_version", "required"},
		{"testdata/reject/schema_v2.yaml", domain.CodeConfigYAMLInvalid, "schema_version", "unsupported"},
		{"testdata/reject/default_command_permit.yaml", domain.CodeConfigYAMLInvalid, "default_command_action", "deny"},
		{"testdata/reject/env_secret.yaml", domain.CodeConfigYAMLInvalid, "shared_secret", "environment"},
		{"testdata/reject/secret_scalar.yaml", domain.CodeConfigYAMLInvalid, "", "mapping"},
		{"testdata/reject/file_and_env.yaml", domain.CodeConfigYAMLInvalid, "shared_secret", "exactly one"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if err == nil {
				t.Fatal("expected error")
			}
			de, ok := domain.AsError(err)
			if !ok {
				t.Fatalf("want domain.Error, got %T %v", err, err)
			}
			if de.Code != tc.code {
				t.Fatalf("code=%s want=%s err=%v", de.Code, tc.code, err)
			}
			if tc.path != "" && !strings.Contains(de.Path, tc.path) && !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("path=%q err=%v", de.Path, err)
			}
			if tc.msg != "" && !strings.Contains(strings.ToLower(err.Error()), tc.msg) {
				t.Fatalf("msg %q not in %v", tc.msg, err)
			}
		})
	}
}

func TestSecretScalarDoesNotEchoCanary(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/reject/secret_scalar.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	canary := "unit-test-canary-secret-xyz"
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error echoed secret: %v", err)
	}
}

func TestOversizedAndInvalidUTF8(t *testing.T) {
	t.Parallel()
	_, err := ParseWithOptions([]byte("schema_version: 1\n"), Options{MaxBytes: 4})
	if err == nil {
		t.Fatal("oversized")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeConfigYAMLInvalid {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("%v", err)
	}

	invalid := []byte("schema_version: 1\nname: ")
	invalid = append(invalid, 0xff, 0xfe, 0xfd)
	if utf8.Valid(invalid) {
		t.Fatal("fixture not invalid utf-8")
	}
	_, err = Parse(invalid)
	if err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("utf8: %v", err)
	}
}

func TestKnownFieldsDecoder(t *testing.T) {
	t.Parallel()
	dec := newStrictDecoder(strings.NewReader("schema_version: 1\nnot_a_field: 1\n"))
	var raw rawFile
	if err := dec.Decode(&raw); err == nil {
		t.Fatal("KnownFields must reject unknown keys")
	}
}

func TestParseEnvSecretWhenEnabled(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 1
security:
  allow_environment_secrets: true
clients:
  - id: c
    match:
      transports: [legacy]
    legacy:
      shared_secret:
        environment: TACLAB_UNIT_TEST_SHARED
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	ref := doc.Clients[0].Legacy.SharedSecret
	if ref.Environment != "TACLAB_UNIT_TEST_SHARED" || ref.File != "" {
		t.Fatalf("%+v", ref)
	}
	if ref.Purpose != credentials.PurposeLegacySharedSecret {
		t.Fatal(ref.Purpose)
	}
}

func TestParseCookieSecureExplicitOverride(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 1
listeners:
  http:
    tls:
      enabled: true
api:
  ui_session:
    cookie_secure: false
`)
	doc, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Listeners.HTTP.TLS.Enabled {
		t.Fatal("tls")
	}
	if doc.API.UISession.CookieSecure {
		t.Fatal("explicit cookie_secure false must win")
	}
}

func TestDuplicateUserIDAfterPrecis(t *testing.T) {
	t.Parallel()
	src := []byte(`
schema_version: 1
users:
  - id: lab-admin
  - id: lab-admin
`)
	_, err := Parse(src)
	if err == nil || !strings.Contains(err.Error(), "duplicate user id") {
		t.Fatalf("%v", err)
	}
}

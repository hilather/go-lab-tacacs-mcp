package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const secretCanary = "unit-test-secret-file-canary-aa11bb22"

func writeSecret(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadSecretFileTrimAndPurpose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := writeSecret(t, dir, "shared", secretCanary+"\n", 0o600)
	ref := SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: p}
	purpose, got, err := ReadSecret(ref, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if purpose != credentials.PurposeLegacySharedSecret {
		t.Fatalf("purpose=%s", purpose)
	}
	sec, ok := got.(credentials.SharedSecret)
	if !ok {
		t.Fatalf("type=%T", got)
	}
	if string(sec.Bytes()) != secretCanary {
		t.Fatalf("bytes=%q", sec.Bytes())
	}
	if strings.Contains(fmt.Sprintf("%v", sec), secretCanary) {
		t.Fatal("holder leaked")
	}
}

func TestReadSecretPreserveTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := writeSecret(t, dir, "v", "abc\n", 0o600)
	ref := SecretRef{Purpose: credentials.PurposeChallengeSecret, File: p, PreserveTrailingNewline: true}
	_, got, err := ReadSecret(ref, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v := got.(credentials.ChallengeSecret)
	if string(v.Bytes()) != "abc\n" {
		t.Fatalf("%q", v.Bytes())
	}
}

func TestReadSecretLoginVerifierRequiresPHC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	plain := writeSecret(t, dir, "plain", "not-a-phc\n", 0o600)
	_, _, err := ReadSecret(SecretRef{Purpose: credentials.PurposeLoginVerifier, File: plain}, ReadOptions{})
	if err == nil {
		t.Fatal("plaintext login verifier must be rejected")
	}
	if strings.Contains(err.Error(), "not-a-phc") {
		t.Fatalf("error leaked verifier: %v", err)
	}
	phc, err := credentials.DeriveArgon2id([]byte("pw"), credentials.TestParams, strings.NewReader("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	good := writeSecret(t, dir, "phc", string(phc)+"\n", 0o600)
	_, got, err := ReadSecret(SecretRef{Purpose: credentials.PurposeLoginVerifier, File: good}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.(credentials.LoginVerifier).Empty() {
		t.Fatal("trimmed PHC")
	}
}

func TestReadSecretRejects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	canaryPath := writeSecret(t, dir, "canary-file", secretCanary, 0o666)
	good := writeSecret(t, dir, "ok", secretCanary, 0o600)
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		ref  SecretRef
		opts ReadOptions
		want string
	}{
		{"missing", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: filepath.Join(dir, "nope")}, ReadOptions{}, "not readable"},
		{"world-writable", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: canaryPath}, ReadOptions{}, "world-writable"},
		{"directory", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: sub}, ReadOptions{}, "directory"},
		{"symlink", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: link}, ReadOptions{}, "symlink"},
		{"env-disabled", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, Environment: "TACLAB_UNIT_TEST_SECRET"}, ReadOptions{}, "disabled"},
		{"env-missing", SecretRef{Purpose: credentials.PurposeLegacySharedSecret, Environment: "TACLAB_UNIT_TEST_SECRET_UNSET"}, ReadOptions{AllowEnvironment: true}, "not set"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ReadSecret(tc.ref, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("want %q in %v", tc.want, err)
			}
			if strings.Contains(err.Error(), secretCanary) {
				t.Fatalf("canary leaked: %v", err)
			}
		})
	}
}

func TestReadSecretEnv(t *testing.T) {
	t.Parallel()
	ref := SecretRef{Purpose: credentials.PurposeAPIBearerToken, Environment: "TACLAB_UNIT_TEST_TOKEN"}
	_, got, err := ReadSecret(ref, ReadOptions{
		AllowEnvironment: true,
		LookupEnv: func(name string) (string, bool) {
			if name == "TACLAB_UNIT_TEST_TOKEN" {
				return secretCanary, true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := got.(credentials.TokenMaterial)
	if string(tok.Bytes()) != secretCanary {
		t.Fatalf("%q", tok.Bytes())
	}
}

func TestReadSecretOversized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := writeSecret(t, dir, "big", strings.Repeat("a", 32), 0o600)
	_, _, err := ReadSecret(SecretRef{Purpose: credentials.PurposeLegacySharedSecret, File: p}, ReadOptions{MaxBytes: 8})
	if err == nil {
		t.Fatal("expected oversized")
	}
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeSecretFileUnreadable {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 8)) {
		t.Fatalf("leaked: %v", err)
	}
}

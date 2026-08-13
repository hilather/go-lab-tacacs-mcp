package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
)

func TestGenerateWritesRestrictedSecretsAndValidYAML(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	res, err := Generate(Options{
		Dir:          dir,
		Force:        true,
		InstanceID:   "labgen-test",
		WriteTimeout: "2s",
		IdleTimeout:  "8s",
		Params:       credentials.TestParams,
		Now:          time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
		Entropy:      bytes.NewReader(bytes.Repeat([]byte("0123456789abcdef"), 64)),
		Stdout:       &stdout,
		Stderr:       &stderr,
	})
	if err != nil {
		t.Fatalf("generate: %v stderr=%s", err, stderr.String())
	}
	if res.Manifest.SharedSecretLength < 32 {
		t.Fatalf("shared secret length %d", res.Manifest.SharedSecretLength)
	}
	if res.Manifest.FileWatchReload {
		t.Fatal("file-watch reload must be off")
	}
	if !strings.Contains(res.Manifest.SourceIPNote, "LAB_DEPLOYMENT") {
		t.Fatalf("source-ip note=%q", res.Manifest.SourceIPNote)
	}

	secretFiles := []string{
		"api_admin_token",
		"lab_switches_tacacs_secret",
		"lab_admin_argon2id",
		"lab_admin_enable_argon2id",
		"lab_readonly_argon2id",
		"lab_disabled_argon2id",
		"lab_admin_challenge_secret",
		"tacacs_server_key.pem",
		"PASSWORDS.txt",
	}
	for _, name := range secretFiles {
		path := filepath.Join(dir, "secrets", name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		want := os.FileMode(0o444)
		if name == "PASSWORDS.txt" {
			want = 0o600
		}
		if st.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want=%o", name, st.Mode().Perm(), want)
		}
	}

	shared, err := os.ReadFile(filepath.Join(dir, "secrets", "lab_switches_tacacs_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.CheckSharedSecret(config.SharedSecretPolicy{
		MinimumLengthCharacters: 16,
		MinimumCharacterClasses: 3,
		RejectKnownWeakValues:   true,
	}, credentials.NewSharedSecret(shared), "legacy"); err != nil {
		t.Fatalf("shared secret policy: %v", err)
	}

	manRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manRaw, shared) {
		t.Fatal("manifest contains shared secret")
	}
	pw, err := os.ReadFile(filepath.Join(dir, "secrets", "PASSWORDS.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manRaw, pw) {
		t.Fatal("manifest contains password file")
	}
	var man Manifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatal(err)
	}
	if man.SecureClientDNS != "nas.lab.example" {
		t.Fatalf("dns=%s", man.SecureClientDNS)
	}

	for _, name := range []string{"server-chain.pem", "client-ca.pem", "client-crl.pem", "server-ca.pem"} {
		if _, err := os.Stat(filepath.Join(dir, "certs-public", name)); err != nil {
			t.Fatalf("public cert %s: %v", name, err)
		}
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "pki", "client-ok.key"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("pki key mode=%o", keyInfo.Mode().Perm())
	}

	dual, err := os.ReadFile(filepath.Join(dir, "config", "taclab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dual, []byte("enabled: true\n    bind: 0.0.0.0:4949")) && !bytes.Contains(dual, []byte("legacy_tacacs:\n    enabled: true")) {
		t.Fatalf("dual config missing enabled legacy:\n%s", dual)
	}
	if !bytes.Contains(dual, []byte("write_timeout: 2s")) {
		t.Fatal("write_timeout not applied")
	}
	if bytes.Contains(dual, shared) || bytes.Contains(dual, []byte("lab-admin=")) {
		t.Fatal("config leaked a secret")
	}

	tlsOnly, err := os.ReadFile(filepath.Join(dir, "config", "taclab.tls-only.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(tlsOnly, []byte("legacy_tacacs:\n    enabled: false")) {
		t.Fatalf("tls-only still has legacy enabled:\n%s", tlsOnly)
	}

	doc, err := config.Load(filepath.Join(dir, "config", "taclab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(doc); err != nil {
		t.Fatal(err)
	}
	if doc.Server.InstanceID != "labgen-test" {
		t.Fatalf("instance=%s", doc.Server.InstanceID)
	}
	if !doc.Listeners.LegacyTACACS.Enabled || !doc.Listeners.SecureTACACS.Enabled {
		t.Fatal("dual listeners")
	}

	tlsDoc, err := config.Load(filepath.Join(dir, "config", "taclab.tls-only.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(tlsDoc); err != nil {
		t.Fatal(err)
	}
	if tlsDoc.Listeners.LegacyTACACS.Enabled {
		t.Fatal("tls-only legacy enabled")
	}

	if _, err := Generate(Options{Dir: dir, Params: credentials.TestParams, Entropy: bytes.NewReader(bytes.Repeat([]byte("x"), 256))}); err == nil {
		t.Fatal("expected refuse without -force")
	}
}

func TestRunHelp(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"-h"}, io.Discard, &stderr)
	if code != 0 && code != 2 {
		t.Fatalf("help exit %d stderr=%s", code, stderr.String())
	}
}

func TestRandomSharedSecretClasses(t *testing.T) {
	sec, err := randomSharedSecret(bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 16)), 40)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.CheckSharedSecret(config.SharedSecretPolicy{
		MinimumLengthCharacters: 32,
		MinimumCharacterClasses: 3,
		RejectKnownWeakValues:   true,
	}, credentials.NewSharedSecret(sec), "s"); err != nil {
		t.Fatal(err)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForbiddenArtifactsDetectsRefplatAndIOLBin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "refplat-2024.iso"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cisco_iol-17.12.01.bin"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits, err := ForbiddenArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) < 2 {
		t.Fatalf("hits=%v", hits)
	}
}

func TestRepoTreeHasNoCiscoBinaries(t *testing.T) {
	hits, err := ForbiddenArtifacts(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("repository must not vendor Cisco images: %v", hits)
	}
}

func TestSanitizeEvidenceRedactsSecrets(t *testing.T) {
	in := "tacacs key supersecret\nAuthorization: Bearer tok123\nplain"
	out := SanitizeEvidenceText(in, "supersecret", "tok123")
	if strings.Contains(out, "supersecret") || strings.Contains(out, "tok123") || strings.Contains(out, "Bearer tok") {
		t.Fatalf("not sanitized: %s", out)
	}
}

func TestParsePasswordsFile(t *testing.T) {
	m := parsePasswordsFile("# x\nlab-admin=AdmX\nlab-admin-enable=EnY\n")
	if m["lab-admin"] != "AdmX" || m["lab-admin-enable"] != "EnY" {
		t.Fatalf("%v", m)
	}
}

func TestRunMainSkipExitZero(t *testing.T) {
	t.Setenv(EnvIOLImage, "")
	// runMain uses OS lookups; unset image is enough.
	code := runMain([]string{"-evidence", filepath.Join(t.TempDir(), "ev.json")})
	if code != 0 {
		t.Fatalf("entry point skip exit=%d", code)
	}
}

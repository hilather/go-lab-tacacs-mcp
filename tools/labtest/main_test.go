package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePasswordsAndCanary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PASSWORDS.txt")
	if err := os.WriteFile(path, []byte("# comment\nlab-admin=secret-one\nlab-readonly=secret-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parsePasswords(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["lab-admin"] != "secret-one" || got["lab-readonly"] != "secret-two" {
		t.Fatalf("%v", got)
	}
	h := &harness{canaries: []string{"secret-one"}}
	if err := h.rejectCanary([]byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := h.rejectCanary([]byte(`token=secret-one`)); err == nil {
		t.Fatal("expected canary")
	}
}

func TestRunUnknownFlag(t *testing.T) {
	if code := run([]string{"-not-a-flag"}); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("TACLAB_HTTP_TEST_X", "http://x")
	if got := envOr("TACLAB_HTTP_TEST_X", "fallback"); got != "http://x" {
		t.Fatalf("%s", got)
	}
	if got := envOr("TACLAB_HTTP_TEST_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("%s", got)
	}
}

func TestTrimNL(t *testing.T) {
	if string(trimNL([]byte("abc\r\n"))) != "abc" {
		t.Fatal(string(trimNL([]byte("abc\r\n"))))
	}
}

func TestMustContain(t *testing.T) {
	if err := mustContain([]byte(`{"id":"lab-admin"}`), "lab-admin"); err != nil {
		t.Fatal(err)
	}
	if err := mustContain([]byte(`{}`), "lab-admin"); err == nil {
		t.Fatal("expected miss")
	}
}

func TestStatusOK(t *testing.T) {
	if err := statusOK(200, nil); err != nil {
		t.Fatal(err)
	}
	if err := statusOK(401, []byte("no")); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("%v", err)
	}
}

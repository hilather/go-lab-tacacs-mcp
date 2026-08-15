package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestParseObservedSourceFailsClosed(t *testing.T) {
	if _, _, err := parseObservedSource([]byte(`{"data":{"items":[]}}`)); err == nil {
		t.Fatal("empty items")
	}
	if _, _, err := parseObservedSource([]byte(`{"data":{"items":[{"client_id":"lab-switches"}]}}`)); err == nil {
		t.Fatal("missing remote")
	}
	id, rem, err := parseObservedSource([]byte(`{"data":{"items":[{"client_id":"lab-switches","remote":"172.18.0.3"}]}}`))
	if err != nil || id != "lab-switches" || rem != "172.18.0.3" {
		t.Fatalf("id=%s rem=%s err=%v", id, rem, err)
	}
}

func TestConsumeSSEPastTimeoutRejectsEarlyClose(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(": keepalive\n\n: keepalive\n\n"))
		_ = pw.Close()
	}()
	if _, err := consumeSSEPastTimeout(pr, 80*time.Millisecond); err == nil {
		t.Fatal("expected failure when stream ends before write_timeout")
	}
}

func TestParseStatusListeners(t *testing.T) {
	raw := []byte(`{"data":{"listeners":[{"id":"legacy_tacacs","enabled":true,"ready":true},{"id":"radius_access","enabled":true,"ready":true,"protocol":"radius","transport":"udp"}]}}`)
	got, err := parseStatusListeners(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !tacacsListenerReady(got, "legacy_tacacs") {
		t.Fatal("legacy")
	}
	if !radiusListenerReady(got, "radius_access") {
		t.Fatal("radius")
	}
	if radiusListenerReady(got, "radius_accounting") {
		t.Fatal("missing accounting must not be ready")
	}
}

func TestParseStatusListenersMissing(t *testing.T) {
	if _, err := parseStatusListeners([]byte(`{"data":{}}`)); err == nil {
		t.Fatal("expected missing listeners")
	}
}

func TestConsumeSSEPastTimeoutRequiresPostTimeoutFrame(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(": keepalive\n\n"))
		time.Sleep(60 * time.Millisecond)
		_, _ = pw.Write([]byte(": keepalive\n\n"))
		_ = pw.Close()
	}()
	buf, err := consumeSSEPastTimeout(pr, 40*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "keepalive") {
		t.Fatalf("body=%q", buf)
	}
}

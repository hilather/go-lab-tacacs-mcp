package aaa

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	testPassword  = "labpass1!"
	testEnablePW  = "enablepass1!"
	testChallenge = "chap-secret-16ch!"
	testSecret    = "LabSecret-16chars!"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func testPHC(t testing.TB) []byte {
	t.Helper()
	enc, err := credentials.DeriveArgon2id([]byte(testPassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func writeSkeleton(t testing.TB, extra string) (string, config.SecretLookup, *state.Manager) {
	t.Helper()
	dir := t.TempDir()
	phc := testPHC(t)
	en, err := credentials.DeriveArgon2id([]byte(testEnablePW), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	enable := filepath.Join(dir, "enable")
	chal := filepath.Join(dir, "chal")
	sec := filepath.Join(dir, "shared")
	for _, f := range []struct {
		path string
		data []byte
	}{
		{login, phc},
		{enable, en},
		{chal, []byte(testChallenge)},
		{sec, []byte(testSecret)},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := `
schema_version: 1
server:
  instance_id: skeleton
listeners:
  legacy_tacacs: {enabled: true, bind: 127.0.0.1:0}
  secure_tacacs: {enabled: false}
  http: {enabled: true, bind: 127.0.0.1:0}
clients:
  - id: lab-switches
    priority: 10
    match:
      source_cidrs: ["127.0.0.0/8", "::1/128"]
      transports: [legacy]
    legacy:
      shared_secret: {file: ` + sec + `}
    authentication:
      allowed_methods: [ascii, pap, chap, mschapv1, mschapv2, enable, ascii_chpass]
groups:
  - id: administrators
    priority: 10
    services:
      - service: shell
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "15"
    command_rules:
      - id: permit-configure
        priority: 10
        action: permit
        command: {exact: configure}
        arguments: {pattern: ".*"}
    default_command_action: deny
  - id: readonly
    priority: 100
    services:
      - service: shell
        action: permit
        reply_attributes:
          - name: priv-lvl
            separator: "="
            value: "1"
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
      - id: deny-everything-else
        priority: 10000
        action: deny
        command: {pattern: ".*"}
        arguments: {pattern: ".*"}
    default_command_action: deny
users:
  - id: lab-admin
    group_ids: [administrators]
    credentials:
      login:
        verifier: {file: ` + login + `}
      challenge:
        secret: {file: ` + chal + `}
      enable:
        verifier: {file: ` + enable + `}
  - id: lab-readonly
    group_ids: [readonly]
    credentials:
      login:
        verifier: {file: ` + login + `}
` + extra
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) {
		b, err := os.ReadFile(ref.File)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	}
	mgr, err := state.New(doc, state.Options{
		Clock:   fixedClock{t: time.Date(2026, 8, 12, 16, 0, 0, 0, time.UTC)},
		Secrets: lookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, lookup, mgr
}

func testService(t testing.TB) (*Service, *state.Manager, *events.Ring) {
	t.Helper()
	_, lookup, mgr := writeSkeleton(t, "")
	ring := events.New(32, domain.SystemClock{})
	svc, err := New(Options{
		Manager: mgr,
		Secrets: lookup,
		Events:  ring,
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, mgr, ring
}

package state

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func mustParse(t *testing.T, src string) *config.Document {
	t.Helper()
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustMgr(t *testing.T, src string) *Manager {
	t.Helper()
	m, err := New(mustParse(t, src), Options{Clock: fixedClock{t: time.Date(2026, 8, 12, 15, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

func intPtr(i int) *int { return &i }

const smallYAML = `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: sw
    display_name: Switches
    priority: 100
    match:
      source_cidrs: ["10.20.0.0/16", "2001:db8:20::/48"]
      transports: [legacy]
    legacy:
      shared_secret: {file: /run/secrets/sw}
    authorization:
      default_group_ids: [ops]
groups:
  - id: ops
    display_name: Operators
    priority: 10
    command_rules:
      - id: show
        priority: 10
        action: permit
        command: {exact: show}
        arguments: {pattern: ".*"}
users:
  - id: alice
    display_name: Alice
    group_ids: [ops]
    credentials:
      login:
        verifier: {file: /run/secrets/alice-login}
      challenge:
        secret: {file: /run/secrets/alice-chal}
      enable:
        verifier: {file: /run/secrets/alice-enable}
`

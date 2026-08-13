package state

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestLifecycleCountsSkipTLSOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	src := `
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
    priority: 10
    match: {source_cidrs: ["10.0.0.0/8"], transports: [legacy]}
    legacy:
      shared_secret: {file: /run/secrets/legacy}
      shared_secret_lifecycle:
        last_rotated_at: 2026-08-02T00:00:00Z
        rotation_interval: 90d
  - id: tls-only
    priority: 20
    match: {source_cidrs: ["10.1.0.0/16"], transports: [tls]}
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	good := []byte("Str0ng-Shared-Secret!!")
	lookup := func(config.SecretRef) ([]byte, error) {
		cp := append([]byte(nil), good...)
		return cp, nil
	}
	m, err := New(doc, Options{Clock: fixedClock{t: now}, Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	counts := m.Snapshot().LifecycleCounts()
	if counts[domain.LifecycleUnknown] != 0 {
		t.Fatalf("unknown=%d counts=%v", counts[domain.LifecycleUnknown], counts)
	}
	if counts[domain.LifecycleCurrent] != 1 {
		t.Fatalf("current=%d", counts[domain.LifecycleCurrent])
	}
	if m.Snapshot().SecretWarningCount() != 0 {
		t.Fatalf("warnings=%d", m.Snapshot().SecretWarningCount())
	}

	// Missing rotation metadata on the legacy secret is unknown, still not a warning.
	doc.Clients[0].Legacy.SharedSecretLifecycle = config.SecretLifecycleMeta{}
	m2, err := New(doc, Options{Clock: fixedClock{t: now}, Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	counts = m2.Snapshot().LifecycleCounts()
	if counts[domain.LifecycleUnknown] != 1 {
		t.Fatalf("legacy without rotation meta unknown=%d", counts[domain.LifecycleUnknown])
	}
	if m2.Snapshot().SecretWarningCount() != 0 {
		t.Fatalf("unknown rotation is not a warning: %d", m2.Snapshot().SecretWarningCount())
	}
}

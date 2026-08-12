package domain

import (
	"testing"
	"time"
)

func TestObjectSourceRejectsTombstone(t *testing.T) {
	t.Parallel()
	for _, s := range []ObjectSource{SourceConfig, SourceRuntime, SourceOverride} {
		if !s.Valid() {
			t.Fatalf("%q must be valid", s)
		}
		got, err := ParseObjectSource(string(s))
		if err != nil || got != s {
			t.Fatalf("ParseObjectSource(%q)=%q err=%v", s, got, err)
		}
	}
	if ObjectSource("tombstone").Valid() {
		t.Fatal("tombstone must not be a valid ObjectSource")
	}
	if _, err := ParseObjectSource("tombstone"); err == nil {
		t.Fatal("ParseObjectSource(tombstone) must fail")
	}
	if ObjectSource("").Valid() {
		t.Fatal("empty source must be invalid")
	}
}

func TestTombstoneIsDeletedNotSource(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	ts := NewTombstone(KindUser, "lab-admin", "actor-1", 9, at)
	if !ts.Deleted {
		t.Fatal("tombstone Deleted must be true")
	}
	if ts.Kind != KindUser || ts.ID != "lab-admin" || ts.ActorID != "actor-1" || ts.AtRevision != 9 {
		t.Fatalf("tombstone fields: %+v", ts)
	}
	if err := ts.Validate(); err != nil {
		t.Fatal(err)
	}
	ts.Deleted = false
	if err := ts.Validate(); err == nil {
		t.Fatal("tombstone with Deleted=false must fail validation")
	}
}

func TestObjectMetaEffectiveRevisionIsSnapshotAlias(t *testing.T) {
	t.Parallel()
	m := ObjectMeta{
		ID:              "lab-admin",
		Kind:            KindUser,
		Source:          SourceConfig,
		RevisionCreated: 1,
		RevisionUpdated: 1,
		Enabled:         true,
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	view := m.WithSnapshotRevision(42)
	if view.EffectiveRevision != 42 {
		t.Fatalf("effective_revision=%d, want 42", view.EffectiveRevision)
	}
	if m.EffectiveRevision != 0 {
		t.Fatalf("WithSnapshotRevision mutated the original: %d", m.EffectiveRevision)
	}
	if view.RevisionCreated != 1 || view.RevisionUpdated != 1 {
		t.Fatal("object revision_created/updated must stay distinct from the snapshot alias")
	}
}

func TestObjectMetaRejectsTombstoneSource(t *testing.T) {
	t.Parallel()
	m := ObjectMeta{ID: "x", Source: ObjectSource("tombstone")}
	if err := m.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
	m.Source = SourceOverride
	m.ShadowsSource = ObjectSource("tombstone")
	if err := m.Validate(); err == nil {
		t.Fatal("expected shadows_source validation error")
	}
}

func TestObjectMetaRequiresID(t *testing.T) {
	t.Parallel()
	m := ObjectMeta{Source: SourceRuntime}
	if err := m.Validate(); err == nil {
		t.Fatal("expected missing id error")
	}
}

func TestTypedIDsAreDistinct(t *testing.T) {
	t.Parallel()
	var user UserID = "lab-admin"
	var group GroupID = "administrators"
	if ObjectID(user) == ObjectID(group) {
		t.Fatal("unexpected equal object ids")
	}
	_ = []ObjectKind{KindUser, KindGroup, KindClient, KindToken, KindRule, KindListener}
}

func TestSecretLifecycle(t *testing.T) {
	t.Parallel()
	for _, s := range []SecretLifecycle{LifecycleCurrent, LifecycleDueSoon, LifecycleOverdue, LifecycleUnknown} {
		if !s.Valid() {
			t.Fatalf("%q", s)
		}
	}
	if SecretLifecycle("ok").Valid() {
		t.Fatal("unknown lifecycle must be invalid")
	}
}

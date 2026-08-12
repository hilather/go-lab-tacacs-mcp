package domain

import "time"

// Revision is the published snapshot number. It increments once per successful
// compile (mutation, reset, or reload).
type Revision uint64

// ObjectSource is the administrative origin of an object.
// Allowed values are config, runtime, and override. Tombstone is not a source.
type ObjectSource string

const (
	SourceConfig   ObjectSource = "config"
	SourceRuntime  ObjectSource = "runtime"
	SourceOverride ObjectSource = "override"
)

// Valid reports whether s is one of the three allowed source values.
func (s ObjectSource) Valid() bool {
	switch s {
	case SourceConfig, SourceRuntime, SourceOverride:
		return true
	default:
		return false
	}
}

func (s ObjectSource) String() string { return string(s) }

// ParseObjectSource accepts only config, runtime, and override.
func ParseObjectSource(v string) (ObjectSource, error) {
	s := ObjectSource(v)
	if !s.Valid() {
		return "", NewError(CodeInvalidArgument, "object source must be config, runtime, or override")
	}
	return s, nil
}

// ObjectKind names an administratively visible object class.
type ObjectKind string

const (
	KindUser     ObjectKind = "user"
	KindGroup    ObjectKind = "group"
	KindClient   ObjectKind = "client"
	KindToken    ObjectKind = "token"
	KindRule     ObjectKind = "rule"
	KindListener ObjectKind = "listener"
)

func (k ObjectKind) String() string { return string(k) }

// Stable object identifiers. UserID is the TACACS username after
// UsernameCasePreserved (applied by the loader, not this package).
type (
	ObjectID   string
	UserID     string
	GroupID    string
	ClientID   string
	TokenID    string
	RuleID     string
	ListenerID string
)

// ObjectMeta is the common administrative view of an object.
// EffectiveRevision is a read alias of the snapshot revision the view was
// loaded from; it is not a third competing revision field.
type ObjectMeta struct {
	ID                ObjectID
	Kind              ObjectKind
	DisplayName       string
	Source            ObjectSource
	ShadowsSource     ObjectSource // empty when the object does not shadow another
	Deleted           bool
	RevisionCreated   Revision
	RevisionUpdated   Revision
	EffectiveRevision Revision
	Enabled           bool
	Labels            map[string]string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// WithSnapshotRevision returns a copy whose EffectiveRevision equals the
// published snapshot revision this view was read from.
func (m ObjectMeta) WithSnapshotRevision(rev Revision) ObjectMeta {
	m.EffectiveRevision = rev
	return m
}

// Validate enforces local metadata invariants. source must never be tombstone.
func (m ObjectMeta) Validate() error {
	if m.ID == "" {
		return NewError(CodeInvalidArgument, "object id is required")
	}
	if !m.Source.Valid() {
		return NewError(CodeInvalidArgument, "object source must be config, runtime, or override")
	}
	if m.ShadowsSource != "" && !m.ShadowsSource.Valid() {
		return NewError(CodeInvalidArgument, "shadows_source must be config, runtime, or override")
	}
	return nil
}

// Tombstone is a distinct overlay entry kind for a deleted baseline object.
// It is not an ObjectSource value. Deleted is always true.
type Tombstone struct {
	Kind       ObjectKind
	ID         ObjectID
	Deleted    bool
	ActorID    string
	AtRevision Revision
	At         time.Time
}

// NewTombstone records a baseline deletion. Deleted is always set.
func NewTombstone(kind ObjectKind, id ObjectID, actor string, rev Revision, at time.Time) Tombstone {
	return Tombstone{
		Kind:       kind,
		ID:         id,
		Deleted:    true,
		ActorID:    actor,
		AtRevision: rev,
		At:         at,
	}
}

// Validate reports whether t is a well-formed tombstone.
func (t Tombstone) Validate() error {
	if t.ID == "" {
		return NewError(CodeInvalidArgument, "tombstone id is required")
	}
	if !t.Deleted {
		return NewError(CodeInvalidArgument, "tombstone deleted flag must be true")
	}
	return nil
}

// Clock is an injectable time source. Production uses SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock returns time.Now in UTC.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// Entropy is an injectable random source. Production uses crypto/rand.Reader.
type Entropy interface {
	Read(p []byte) (int, error)
}

// SecretLifecycle is non-secret compiled health for a legacy shared secret.
type SecretLifecycle string

const (
	LifecycleCurrent SecretLifecycle = "current"
	LifecycleDueSoon SecretLifecycle = "due_soon"
	LifecycleOverdue SecretLifecycle = "overdue"
	LifecycleUnknown SecretLifecycle = "unknown"
)

func (s SecretLifecycle) Valid() bool {
	switch s {
	case LifecycleCurrent, LifecycleDueSoon, LifecycleOverdue, LifecycleUnknown:
		return true
	default:
		return false
	}
}

func (s SecretLifecycle) String() string { return string(s) }

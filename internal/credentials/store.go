package credentials

import (
	"sync"
	"time"
)

// Record is the non-protocol material needed to verify one user.
// Login and Enable are Argon2id PHC strings. Challenge is clear-equivalent.
type Record struct {
	ID          string
	Enabled     bool
	Restricted  bool
	Login       LoginVerifier
	Challenge   ChallengeSecret
	Enable      EnableVerifier
	ValidAfter  *time.Time
	ValidBefore *time.Time
}

// Capabilities is secret-free presence metadata.
type Capabilities struct {
	Login     bool
	Challenge bool
	Enable    bool
}

// Caps reports which methods have material. It does not inspect validity.
func (r Record) Caps() Capabilities {
	return Capabilities{
		Login:     !r.Login.Empty(),
		Challenge: !r.Challenge.Empty(),
		Enable:    !r.Enable.Empty(),
	}
}

// Store looks up credential material by already-canonical user id.
type Store interface {
	Lookup(userID string) (Record, bool)
}

// Memory is a process-local Store for tests and runtime-derived material.
type Memory struct {
	mu    sync.RWMutex
	users map[string]Record
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{users: map[string]Record{}}
}

// Put copies r under r.ID (caller should pass a UsernameCasePreserved id).
func (m *Memory) Put(r Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.users == nil {
		m.users = map[string]Record{}
	}
	m.users[r.ID] = cloneRecord(r)
}

func cloneRecord(r Record) Record {
	out := Record{
		ID:         r.ID,
		Enabled:    r.Enabled,
		Restricted: r.Restricted,
		Login:      NewLoginVerifier(r.Login.Bytes()),
		Challenge:  NewChallengeSecret(r.Challenge.Bytes()),
		Enable:     NewEnableVerifier(r.Enable.Bytes()),
	}
	if r.ValidAfter != nil {
		t := r.ValidAfter.UTC()
		out.ValidAfter = &t
	}
	if r.ValidBefore != nil {
		t := r.ValidBefore.UTC()
		out.ValidBefore = &t
	}
	return out
}

// Delete removes id if present.
func (m *Memory) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, id)
}

// Lookup implements Store.
func (m *Memory) Lookup(userID string) (Record, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.users[userID]
	if !ok {
		return Record{}, false
	}
	return cloneRecord(r), true
}

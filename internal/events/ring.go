package events

import (
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const defaultCapacity = 10000

// Event is one redacted ring entry.
type Event struct {
	ID        uint64          `json:"id"`
	Time      time.Time       `json:"time"`
	Category  string          `json:"category"`
	Type      string          `json:"type"`
	Result    string          `json:"result"`
	Transport string          `json:"transport,omitempty"`
	ClientID  string          `json:"client_id,omitempty"`
	SessionID uint32          `json:"session_id,omitempty"`
	Revision  domain.Revision `json:"revision,omitempty"`
	UserID    string          `json:"user_id,omitempty"`
	Command   string          `json:"command,omitempty"`
}

// Ring is a bounded, overwrite-oldest event sink. It is safe for concurrent use.
type Ring struct {
	mu          sync.Mutex
	clock       domain.Clock
	cap         int
	seq         uint64
	buf         []Event
	start       int
	n           int
	overwritten uint64
}

// New returns a ring with capacity entries. Capacity <= 0 uses 10_000.
func New(capacity int, clock domain.Clock) *Ring {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &Ring{clock: clock, cap: capacity, buf: make([]Event, capacity)}
}

// Accept assigns an ID and timestamp and stores e. The stored copy is returned.
func (r *Ring) Accept(e Event) Event {
	if r == nil {
		return Event{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.ID = r.seq
	if e.Time.IsZero() {
		e.Time = r.clock.Now().UTC()
	}
	if r.n == r.cap {
		r.buf[r.start] = e
		r.start = (r.start + 1) % r.cap
		r.overwritten++
		return e
	}
	r.buf[(r.start+r.n)%r.cap] = e
	r.n++
	return e
}

// Len is the number of retained events.
func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// Overwritten is how many events were dropped because the ring was full.
func (r *Ring) Overwritten() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.overwritten
}

// Latest returns the most recently accepted event, if any.
func (r *Ring) Latest() (Event, bool) {
	if r == nil {
		return Event{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == 0 {
		return Event{}, false
	}
	idx := (r.start + r.n - 1) % r.cap
	return r.buf[idx], true
}

// Snapshot returns retained events in id order (oldest first).
func (r *Ring) Snapshot() []Event {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, r.n)
	for i := 0; i < r.n; i++ {
		out[i] = r.buf[(r.start+i)%r.cap]
	}
	return out
}

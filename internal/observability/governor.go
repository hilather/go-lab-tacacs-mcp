package observability

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Semaphore is a non-blocking occupancy cap.
type Semaphore struct {
	cap    int
	tokens chan struct{}
	active atomic.Int64
}

// NewSemaphore returns a cap-sized semaphore. cap <= 0 means unlimited.
func NewSemaphore(cap int) *Semaphore {
	s := &Semaphore{cap: cap}
	if cap > 0 {
		s.tokens = make(chan struct{}, cap)
	}
	return s
}

// TryAcquire reserves one slot. The caller must Release on success.
func (s *Semaphore) TryAcquire() bool {
	if s == nil {
		return true
	}
	if s.tokens == nil {
		s.active.Add(1)
		return true
	}
	select {
	case s.tokens <- struct{}{}:
		s.active.Add(1)
		return true
	default:
		return false
	}
}

// Acquire waits until a slot is free or ctx is done.
func (s *Semaphore) Acquire(ctx context.Context) error {
	if s == nil || s.tokens == nil {
		if s != nil {
			s.active.Add(1)
		}
		return nil
	}
	select {
	case s.tokens <- struct{}{}:
		s.active.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot taken by TryAcquire or Acquire.
func (s *Semaphore) Release() {
	if s == nil {
		return
	}
	s.active.Add(-1)
	if s.tokens != nil {
		select {
		case <-s.tokens:
		default:
		}
	}
}

// Active is the number of held slots.
func (s *Semaphore) Active() int {
	if s == nil {
		return 0
	}
	return int(s.active.Load())
}

// Cap is the configured maximum, or 0 for unlimited.
func (s *Semaphore) Cap() int {
	if s == nil {
		return 0
	}
	return s.cap
}

// FieldLimits are protocol and API field caps.
type FieldLimits struct {
	MaxUsernameBytes          int
	MaxPortBytes              int
	MaxRemoteAddressBytes     int
	MaxAuthenticationRounds   int
	MaxAuthorizationArguments int
	MaxArgumentBytes          int
	MaxCommandBytes           int
	MaxPolicyTraceSteps       int
	MaxEventPayloadBytes      int
	MaxRequestBodyBytes       int64
	MaxPacketBodyBytes        uint32
	MaxObjectsUsers           int
	MaxObjectsGroups          int
	MaxObjectsClients         int
	MaxObjectsTokens          int
}

// DefaultFieldLimits matches configuration defaults.
func DefaultFieldLimits() FieldLimits {
	return FieldLimits{
		MaxUsernameBytes:          253,
		MaxPortBytes:              253,
		MaxRemoteAddressBytes:     253,
		MaxAuthenticationRounds:   16,
		MaxAuthorizationArguments: 256,
		MaxArgumentBytes:          65535,
		MaxCommandBytes:           65535,
		MaxPolicyTraceSteps:       1000,
		MaxEventPayloadBytes:      65536,
		MaxRequestBodyBytes:       2097152,
		MaxPacketBodyBytes:        65536,
		MaxObjectsUsers:           10000,
		MaxObjectsGroups:          1000,
		MaxObjectsClients:         2000,
		MaxObjectsTokens:          1000,
	}
}

// CheckBytes rejects a field that exceeds max.
func CheckBytes(name string, b []byte, max int) error {
	if max <= 0 || len(b) <= max {
		return nil
	}
	return domain.NewError(domain.CodeInvalidArgument, "field exceeds configured limit").
		WithPath(name).
		WithDetail("length", len(b)).
		WithDetail("max", max)
}

// CheckCount rejects a collection that exceeds max.
func CheckCount(name string, n, max int) error {
	if max <= 0 || n <= max {
		return nil
	}
	return domain.NewError(domain.CodeObjectLimitExceeded, "object or field count exceeds configured limit").
		WithPath(name).
		WithDetail("count", n).
		WithDetail("max", max)
}

// Governor bundles connection/session semaphores and field limits.
type Governor struct {
	Connections *Semaphore
	Sessions    *Semaphore
	Fields      FieldLimits

	mu       sync.Mutex
	inflight int
	maxIn    int
}

// NewGovernor constructs connection and session caps.
func NewGovernor(maxConn, maxSess int, fields FieldLimits) *Governor {
	if fields.MaxPacketBodyBytes == 0 {
		fields = DefaultFieldLimits()
	}
	return &Governor{
		Connections: NewSemaphore(maxConn),
		Sessions:    NewSemaphore(maxSess),
		Fields:      fields,
		maxIn:       256,
	}
}

// TryInFlight reserves a generic worker slot.
func (g *Governor) TryInFlight() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.maxIn > 0 && g.inflight >= g.maxIn {
		return false
	}
	g.inflight++
	return true
}

// ReleaseInFlight frees a generic worker slot.
func (g *Governor) ReleaseInFlight() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.inflight > 0 {
		g.inflight--
	}
	g.mu.Unlock()
}

// WithTimeout returns ctx cancelled after d, or ctx if d <= 0.
func WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

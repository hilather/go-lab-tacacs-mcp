package udp

import (
	"sync"
	"time"
)

const limiterSweepCap = 8192

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// sourceLimiter is a per-source token bucket. Unknown clients never
// allocate a bucket — the caller matches the RADIUSIndex first.
type sourceLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	now   func() time.Time
	items map[string]*tokenBucket
}

func newSourceLimiter(rate float64, burst int, now func() time.Time) *sourceLimiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &sourceLimiter{
		rate:  rate,
		burst: float64(burst),
		now:   now,
		items: make(map[string]*tokenBucket),
	}
}

func (l *sourceLimiter) Allow(src string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.items) > limiterSweepCap {
		l.sweepLocked(now)
	}
	b := l.items[src]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.items[src] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *sourceLimiter) sweepLocked(now time.Time) {
	idle := 2 * time.Minute
	for k, b := range l.items {
		if now.Sub(b.last) > idle {
			delete(l.items, k)
		}
	}
}

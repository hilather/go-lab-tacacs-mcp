package rest

import (
	"sync"
	"time"
)

type limiter struct {
	mu sync.Mutex
	by map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter {
	return &limiter{by: map[string]*bucket{}}
}

func (l *limiter) allow(key string, rate float64, burst int, now time.Time) bool {
	if l == nil {
		return true
	}
	if rate <= 0 || burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.by[key]
	if b == nil {
		b = &bucket{tokens: float64(burst), last: now}
		l.by[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

package udp

import (
	"testing"
	"time"
)

func TestSourceLimiterBurstThenRefill(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	l := newSourceLimiter(100, 2, func() time.Time { return now })
	first := l.Allow("127.0.0.1")
	second := l.Allow("127.0.0.1")
	if !first || !second {
		t.Fatal("burst")
	}
	if l.Allow("127.0.0.1") {
		t.Fatal("over burst")
	}
	now = now.Add(20 * time.Millisecond)
	if !l.Allow("127.0.0.1") {
		t.Fatal("refill")
	}
}

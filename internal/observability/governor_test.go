package observability

import (
	"context"
	"testing"
	"time"
)

func TestSemaphoreSaturation(t *testing.T) {
	t.Parallel()
	s := NewSemaphore(2)
	if !s.TryAcquire() {
		t.Fatal("expected first slot")
	}
	if !s.TryAcquire() {
		t.Fatal("expected second slot")
	}
	if s.TryAcquire() {
		t.Fatal("cap should reject")
	}
	if s.Active() != 2 {
		t.Fatalf("active=%d", s.Active())
	}
	s.Release()
	if !s.TryAcquire() {
		t.Fatal("release should free a slot")
	}
}

func TestSemaphoreCancel(t *testing.T) {
	t.Parallel()
	s := NewSemaphore(1)
	if !s.TryAcquire() {
		t.Fatal("first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Acquire(ctx); err == nil {
		t.Fatal("expected cancel")
	}
}

func TestFieldLimits(t *testing.T) {
	t.Parallel()
	if err := CheckBytes("user", make([]byte, 10), 8); err == nil {
		t.Fatal("expected overflow")
	}
	if err := CheckBytes("user", make([]byte, 8), 8); err != nil {
		t.Fatal(err)
	}
	if err := CheckCount("users", 5, 4); err == nil {
		t.Fatal("expected count overflow")
	}
}

func TestGovernorInFlight(t *testing.T) {
	t.Parallel()
	g := NewGovernor(1, 1, DefaultFieldLimits())
	g.maxIn = 1
	if !g.TryInFlight() {
		t.Fatal("first inflight")
	}
	if g.TryInFlight() {
		t.Fatal("inflight cap")
	}
	g.ReleaseInFlight()
	if !g.TryInFlight() {
		t.Fatal("after release")
	}
}

func TestWithTimeout(t *testing.T) {
	t.Parallel()
	ctx, cancel := WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	<-ctx.Done()
}

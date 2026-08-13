package observability

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSaturationAndShutdown(t *testing.T) {
	t.Parallel()
	g := NewGovernor(8, 8, DefaultFieldLimits())
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !g.Connections.TryAcquire() {
				return
			}
			defer g.Connections.Release()
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}()
	}
	deadline := time.After(2 * time.Second)
	for g.Connections.Active() == 0 {
		select {
		case <-deadline:
			t.Fatal("no occupancy")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if g.Connections.Active() > g.Connections.Cap() {
		t.Fatalf("over cap %d", g.Connections.Active())
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("leak: workers did not exit")
	}
	if g.Connections.Active() != 0 {
		t.Fatalf("active after shutdown %d", g.Connections.Active())
	}
}

func TestSlowObserverDoesNotBlock(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rec := NewRecorder(reg)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		rec.EventSubscriberReset()
		rec.Authen(TransportLegacy, "ascii", "fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("metrics recording too slow")
	}
}

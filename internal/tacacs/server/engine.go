package server

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Engine tracks global connection occupancy and coordinates drain.
type Engine struct {
	Limits  Limits
	Handler Handler
	Logger  *slog.Logger

	sem    chan struct{}
	wg     sync.WaitGroup
	active atomic.Int64
	once   sync.Once
}

func (e *Engine) init() {
	e.once.Do(func() {
		e.Limits = e.Limits.normalized()
		if e.Handler == nil {
			e.Handler = Stub{}
		}
		if e.Logger == nil {
			e.Logger = slog.Default()
		}
		if e.Limits.MaxConnections > 0 {
			e.sem = make(chan struct{}, e.Limits.MaxConnections)
		}
	})
}

// Active is the number of connections currently inside Serve.
func (e *Engine) Active() int {
	if e == nil {
		return 0
	}
	return int(e.active.Load())
}

// TryAcquire reserves a connection slot. The caller must Release.
func (e *Engine) TryAcquire() bool {
	e.init()
	if e.sem == nil {
		e.active.Add(1)
		return true
	}
	select {
	case e.sem <- struct{}{}:
		e.active.Add(1)
		return true
	default:
		return false
	}
}

// Release frees a slot taken by TryAcquire.
func (e *Engine) Release() {
	e.active.Add(-1)
	if e.sem != nil {
		select {
		case <-e.sem:
		default:
		}
	}
}

// Serve runs one bound connection. It occupies a slot for the duration.
func (e *Engine) Serve(ctx context.Context, pio PacketIO, id Identity) error {
	e.init()
	if !e.TryAcquire() {
		_ = pio.Close()
		return ErrConnLimit
	}
	e.wg.Add(1)
	defer e.wg.Done()
	defer e.Release()
	return ServeConn(ctx, pio, id, e.Limits, e.Handler)
}

// Drain waits for in-flight Serve calls up to the configured grace period.
func (e *Engine) Drain(ctx context.Context) {
	e.init()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(e.Limits.ShutdownGrace)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-timer.C:
	}
}

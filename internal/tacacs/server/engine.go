package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

// Engine tracks global connection occupancy and coordinates drain.
type Engine struct {
	Limits   Limits
	Handler  Handler
	Metrics  *observability.Recorder
	Listener string

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
		if e.Limits.MaxConnections > 0 {
			e.sem = make(chan struct{}, e.Limits.MaxConnections)
		}
	})
}

// Prepare initializes the engine so Accept can check the cap immediately.
func (e *Engine) Prepare() { e.init() }

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

// Serve acquires a slot and runs one bound connection.
func (e *Engine) Serve(ctx context.Context, pio PacketIO, id Identity) error {
	e.init()
	if !e.TryAcquire() {
		_ = pio.Close()
		e.Metrics.ConnectionRejected(e.listenerName(), transportOf(id), "conn_limit")
		return ErrConnLimit
	}
	return e.ServeHeld(ctx, pio, id)
}

// ServeHeld runs a connection that already holds a slot from TryAcquire.
func (e *Engine) ServeHeld(ctx context.Context, pio PacketIO, id Identity) error {
	e.init()
	e.wg.Add(1)
	defer e.wg.Done()
	defer e.Release()
	tr := transportOf(id)
	ln := e.listenerName()
	e.Metrics.ConnectionAccepted(ln, tr)
	defer e.Metrics.ConnectionClosed(ln, tr)
	return ServeConnMetrics(ctx, pio, id, e.Limits, e.Handler, e.Metrics, ln)
}

func (e *Engine) listenerName() string {
	if e != nil && e.Listener != "" {
		return e.Listener
	}
	return observability.ListenerLegacy
}

func transportOf(id Identity) string {
	if id.Transport == "" {
		return observability.TransportLegacy
	}
	return string(id.Transport)
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

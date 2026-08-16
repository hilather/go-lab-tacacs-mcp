package tls

import (
	"context"
	"errors"
	"net"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
)

// ID is the configuration key for this RADIUS/TLS socket.
func (l *Listener) ID() string {
	if l == nil || l.opts.ID == "" {
		return runtime.IDRADIUSRadSec
	}
	return l.opts.ID
}

// Protocol is always RADIUS.
func (l *Listener) Protocol() domain.Protocol { return domain.ProtocolRADIUS }

// Carrier is the RADIUS/TLS binding.
func (l *Listener) Carrier() domain.Carrier { return domain.CarrierRADIUSTLS }

// Role is access; the stream also accepts accounting by packet code.
func (l *Listener) Role() domain.ListenerRole { return domain.RoleAccess }

// Ready reports that the accept loop is running.
func (l *Listener) Ready() bool { return l != nil && l.ready.Load() }

// Start runs the accept loop until ctx is cancelled or the listener closes.
func (l *Listener) Start(ctx context.Context) error { return l.Serve(ctx) }

// Serve accepts TLS connections until ctx is cancelled.
func (l *Listener) Serve(ctx context.Context) error {
	if l == nil || l.ln == nil {
		return errors.New("listener is not bound")
	}
	l.ready.Store(true)
	defer l.ready.Store(false)
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || l.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			l.setError("accept")
			return err
		}
		if !l.track(c) {
			_ = c.Close()
			l.note("drop_overload")
			continue
		}
		l.connWG.Add(1)
		go func(nc net.Conn) {
			defer l.connWG.Done()
			defer l.untrack(nc)
			l.handleConn(ctx, nc)
		}(c)
	}
}

// Drain stops accept and waits for in-flight connections.
func (l *Listener) Drain(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.ready.Store(false)
	l.closed.Store(true)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		l.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		l.closeActive()
		return ctx.Err()
	}
}

// Close releases the socket. It does not wait for in-flight work.
func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	l.ready.Store(false)
	l.closed.Store(true)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	l.closeActive()
	return nil
}

// Status is live inventory for the registry.
func (l *Listener) Status() runtime.Status {
	if l == nil {
		return runtime.Status{
			Descriptor: runtime.Descriptor{
				ID:       runtime.IDRADIUSRadSec,
				Protocol: domain.ProtocolRADIUS,
				Carrier:  domain.CarrierRADIUSTLS,
				Roles:    []domain.ListenerRole{domain.RoleAccess, domain.RoleAccounting},
			},
		}
	}
	last, _ := l.lastError.Load().(string)
	return runtime.Status{
		Descriptor: runtime.Descriptor{
			ID:       l.ID(),
			Protocol: domain.ProtocolRADIUS,
			Carrier:  domain.CarrierRADIUSTLS,
			Roles:    []domain.ListenerRole{domain.RoleAccess, domain.RoleAccounting},
			Bind:     l.bindString(),
			Required: l.opts.Required || l.opts.Settings.Required,
		},
		Enabled:       true,
		Ready:         l.Ready(),
		Inflight:      int(l.inflight.Load()),
		QueueDepth:    int(l.conns.Load()),
		LastErrorCode: last,
	}
}

func (l *Listener) bindString() string {
	if addr := l.Addr(); addr != nil {
		return addr.String()
	}
	return l.opts.Bind
}

func (l *Listener) setError(code string) {
	l.lastError.Store(code)
}

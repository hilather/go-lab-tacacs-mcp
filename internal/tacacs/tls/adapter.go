package tls

import (
	"context"
	"errors"
	"net"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
)

var _ runtime.Listener = (*Listener)(nil)

// ID is the configuration key for the secure TACACS socket.
func (l *Listener) ID() string { return runtime.IDSecureTACACS }

// Protocol is always TACACS.
func (l *Listener) Protocol() domain.Protocol { return domain.ProtocolTACACS }

// Carrier is the TLS binding. This is not a domain.Transport value.
func (l *Listener) Carrier() domain.Carrier { return domain.CarrierTACACSTLS }

// Role is the combined TACACS AAA socket.
func (l *Listener) Role() domain.ListenerRole { return domain.RoleAAA }

// Start accepts connections until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error { return l.Serve(ctx) }

// Drain stops accepts and waits for in-flight sessions up to ctx.
func (l *Listener) Drain(ctx context.Context) error { return l.Shutdown(ctx) }

// Close releases the bound socket without waiting for sessions.
func (l *Listener) Close() error {
	if l == nil || l.ln == nil {
		return nil
	}
	l.ready.Store(false)
	err := l.ln.Close()
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Status is live inventory for the registry. Bind is the actual address.
func (l *Listener) Status() runtime.Status {
	if l == nil {
		return runtime.Status{
			Descriptor: runtime.Descriptor{
				ID:       runtime.IDSecureTACACS,
				Protocol: domain.ProtocolTACACS,
				Carrier:  domain.CarrierTACACSTLS,
				Roles:    []domain.ListenerRole{domain.RoleAAA},
			},
		}
	}
	inflight := 0
	if l.engine != nil {
		inflight = l.engine.Active()
	}
	return runtime.Status{
		Descriptor: runtime.Descriptor{
			ID:       runtime.IDSecureTACACS,
			Protocol: domain.ProtocolTACACS,
			Carrier:  domain.CarrierTACACSTLS,
			Roles:    []domain.ListenerRole{domain.RoleAAA},
			Bind:     l.bindString(),
			Required: true,
		},
		Enabled:  true,
		Ready:    l.Ready(),
		Inflight: inflight,
	}
}

func (l *Listener) bindString() string {
	if addr := l.Addr(); addr != nil {
		return addr.String()
	}
	return l.opts.Bind
}

package udp

import (
	"context"
	"errors"
	"net"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
)

// ID is the configuration key for this RADIUS socket.
func (l *Listener) ID() string {
	if l == nil || l.id == "" {
		return runtime.IDRADIUSAccess
	}
	return l.id
}

// Protocol is always RADIUS.
func (l *Listener) Protocol() domain.Protocol { return domain.ProtocolRADIUS }

// Carrier is the RADIUS/UDP binding. This is not a domain.Transport value.
func (l *Listener) Carrier() domain.Carrier { return domain.CarrierRADIUSUDP }

// ChallengeStore is the shared in-memory State table. Close does not Reset it.
func (l *Listener) ChallengeStore() *radiusruntime.ChallengeStore {
	if l == nil {
		return nil
	}
	return l.challenges
}

// Role is access, accounting, or dynamic_authorization.
func (l *Listener) Role() domain.ListenerRole {
	if l == nil {
		return domain.RoleAccess
	}
	return l.role
}

// Ready reports that the receive loop is running.
func (l *Listener) Ready() bool { return l != nil && l.ready.Load() }

// Start runs the receive loop until ctx is cancelled or the socket closes.
func (l *Listener) Start(ctx context.Context) error { return l.Serve(ctx) }

// Serve reads datagrams onto the worker queue.
func (l *Listener) Serve(ctx context.Context) error {
	if l == nil || l.pc == nil {
		return errors.New("listener is not bound")
	}
	l.ready.Store(true)
	defer l.ready.Store(false)
	go func() {
		<-ctx.Done()
		l.closeConn()
	}()
	err := l.receiveLoop()
	l.closeQueue()
	return err
}

func (l *Listener) receiveLoop() error {
	max := l.opts.Settings.MaxPacketBytes
	tmp := make([]byte, max)
	for {
		n, addr, err := l.pc.ReadFrom(tmp)
		if err != nil {
			if l.closed.Load() || ctxClosed(err) {
				return nil
			}
			l.setError("recv")
			return err
		}
		if n == 0 {
			continue
		}
		buf := make([]byte, n)
		copy(buf, tmp[:n])
		item := workItem{buf: buf, src: addr}
		select {
		case l.queue <- item:
			l.queued.Add(1)
			l.observeQueue()
		default:
			wipe(buf)
			l.note(serverReasonOverload)
		}
	}
}

func ctxClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// Drain stops receive and waits for queued work up to ctx.
func (l *Listener) Drain(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.ready.Store(false)
	l.closeConn()
	done := make(chan struct{})
	go func() {
		l.workerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close releases the socket. It does not wait for in-flight work.
func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	l.ready.Store(false)
	l.closeConn()
	l.closeQueue()
	return nil
}

// Status is live inventory for the registry. Bind is the actual address.
func (l *Listener) Status() runtime.Status {
	if l == nil {
		return runtime.Status{
			Descriptor: runtime.Descriptor{
				ID:       runtime.IDRADIUSAccess,
				Protocol: domain.ProtocolRADIUS,
				Carrier:  domain.CarrierRADIUSUDP,
				Roles:    []domain.ListenerRole{domain.RoleAccess},
			},
		}
	}
	last, _ := l.lastError.Load().(string)
	return runtime.Status{
		Descriptor: runtime.Descriptor{
			ID:       l.id,
			Protocol: domain.ProtocolRADIUS,
			Carrier:  domain.CarrierRADIUSUDP,
			Roles:    []domain.ListenerRole{l.role},
			Bind:     l.bindString(),
			Required: l.opts.Required || l.opts.Settings.Required,
		},
		Enabled:       true,
		Ready:         l.Ready(),
		Inflight:      int(l.inflight.Load()),
		QueueDepth:    int(l.queued.Load()),
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

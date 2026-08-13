package legacy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

// Options construct a legacy TCP listener.
type Options struct {
	Bind     string
	Settings config.TACACSListener
	Grace    time.Duration
	Snapshot func() *state.Snapshot
	Secrets  config.SecretLookup
	Handler  server.Handler
	Logger   *slog.Logger
	Listen   func(network, address string) (net.Listener, error)
	Metrics  *observability.Recorder
}

// Listener is the RFC 8907 TCP socket.
type Listener struct {
	ln         net.Listener
	engine     *server.Engine
	opts       Options
	ready      atomic.Bool
	wg         sync.WaitGroup
	connCtx    context.Context
	connCancel context.CancelFunc
}

// Listen binds the configured address. Serve must be called to accept.
func Listen(opts Options) (*Listener, error) {
	if opts.Snapshot == nil {
		return nil, errors.New("snapshot accessor is required")
	}
	if opts.Secrets == nil {
		return nil, errors.New("secret lookup is required")
	}
	if opts.Bind == "" {
		opts.Bind = opts.Settings.Bind
	}
	if opts.Bind == "" {
		return nil, errors.New("bind address is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Handler == nil {
		opts.Handler = server.Stub{}
	}
	listen := opts.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", opts.Bind)
	if err != nil {
		return nil, err
	}
	connCtx, connCancel := context.WithCancel(context.Background())
	eng := &server.Engine{
		Limits:   limitsFrom(opts.Settings, opts.Grace),
		Handler:  opts.Handler,
		Metrics:  opts.Metrics,
		Listener: observability.ListenerLegacy,
	}
	eng.Prepare()
	return &Listener{
		ln:         ln,
		opts:       opts,
		connCtx:    connCtx,
		connCancel: connCancel,
		engine:     eng,
	}, nil
}

func limitsFrom(s config.TACACSListener, grace time.Duration) server.Limits {
	idle := s.IdleTimeout
	if s.SingleConnect.IdleTimeout > 0 {
		idle = s.SingleConnect.IdleTimeout
	}
	return server.Limits{
		MaxConnections:           s.MaxConnections,
		MaxSessionsPerConnection: s.MaxSessionsPerConnection,
		MaxPacketBodyBytes:       uint32(s.MaxPacketBodyBytes),
		ReadTimeout:              s.ReadTimeout,
		WriteTimeout:             s.WriteTimeout,
		IdleTimeout:              idle,
		HandshakeTimeout:         s.HandshakeTimeout,
		SingleConnectEnabled:     s.SingleConnect.Enabled,
		MaxLifetime:              s.SingleConnect.MaxLifetime,
		ShutdownGrace:            grace,
	}
}

// Addr is the bound address (port may be ephemeral).
func (l *Listener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// Ready reports that the accept loop is running.
func (l *Listener) Ready() bool { return l != nil && l.ready.Load() }

// Engine is the shared session engine.
func (l *Listener) Engine() *server.Engine { return l.engine }

// Serve accepts connections until ctx is cancelled or the listener closes.
func (l *Listener) Serve(ctx context.Context) error {
	l.ready.Store(true)
	defer l.ready.Store(false)

	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()

	for {
		c, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		l.wg.Add(1)
		go func(nc net.Conn) {
			defer l.wg.Done()
			// Accept-loop ctx only stops Accept. Sessions drain on Shutdown.
			l.handle(l.connCtx, nc)
		}(c)
	}
}

func (l *Listener) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	if !l.engine.TryAcquire() {
		l.opts.Metrics.ConnectionRejected(observability.ListenerLegacy, observability.TransportLegacy, "conn_limit")
		return
	}
	held := true
	release := func() {
		if held {
			l.engine.Release()
			held = false
		}
	}

	ip := peerIP(nc.RemoteAddr())
	snap := l.opts.Snapshot()
	if snap == nil {
		release()
		l.opts.Logger.Error("legacy reject: no snapshot")
		l.opts.Metrics.ConnectionRejected(observability.ListenerLegacy, observability.TransportLegacy, "unavailable")
		return
	}
	client, err := snap.MatchClient(domain.TransportLegacy, ip, nil)
	if err != nil {
		release()
		l.opts.Logger.Info("legacy reject: unknown client")
		l.opts.Metrics.ConnectionRejected(observability.ListenerLegacy, observability.TransportLegacy, "unknown_client")
		return
	}
	raw, err := l.opts.Secrets(client.Client.Legacy.SharedSecret)
	if err != nil || len(raw) == 0 {
		wipe(raw)
		release()
		l.opts.Logger.Error("legacy reject: shared secret unavailable", "client_id", client.Client.ID)
		l.opts.Metrics.ConnectionRejected(observability.ListenerLegacy, observability.TransportLegacy, "secret_unavailable")
		return
	}
	secret := credentials.NewSharedSecret(raw)
	wipe(raw)

	id := server.Identity{
		ClientID:  client.Client.ID,
		Transport: domain.TransportLegacy,
		Peer:      append(net.IP(nil), ip...),
		Revision:  snap.Revision,
	}
	pio := newConn(nc, secret)
	// ServeHeld releases the slot.
	held = false
	if err := l.engine.ServeHeld(ctx, pio, id); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		l.opts.Logger.Debug("legacy connection ended", "client_id", id.ClientID, "err", err)
	}
}

func peerIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

// Shutdown stops accepts and waits for in-flight sessions up to ctx.
// After ctx expires, remaining connection contexts are cancelled.
func (l *Listener) Shutdown(ctx context.Context) error {
	l.ready.Store(false)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		if l.connCancel != nil {
			l.connCancel()
		}
		return nil
	case <-ctx.Done():
		if l.connCancel != nil {
			l.connCancel()
		}
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		return ctx.Err()
	}
}

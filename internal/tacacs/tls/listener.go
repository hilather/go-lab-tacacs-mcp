package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

// Options construct a secure TACACS+ TLS listener.
type Options struct {
	Bind     string
	Settings config.SecureTACACSListener
	Grace    time.Duration
	Snapshot func() *state.Snapshot
	Secrets  config.SecretLookup
	Handler  server.Handler
	Logger   *slog.Logger
	Listen   func(network, address string) (net.Listener, error)
}

// Listener is the RFC 9887 TLS 1.3 socket.
type Listener struct {
	ln             net.Listener
	engine         *server.Engine
	opts           Options
	tlsCfg         *tls.Config
	profiles       []tlsProfile
	defaultProfile tlsProfile
	requireSNI     bool
	clientCAFile   string
	clientCAs      *x509.CertPool
	clientCACerts  []*x509.Certificate
	crlPath        string
	ready          atomic.Bool
	wg             sync.WaitGroup
	connCtx        context.Context
	connCancel     context.CancelFunc
}

type boundConn struct {
	net.Conn
	identity server.Identity
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
		Limits:  limitsFrom(opts.Settings.TACACSListener, opts.Grace),
		Handler: opts.Handler,
	}
	eng.Prepare()
	l := &Listener{
		ln:         ln,
		opts:       opts,
		connCtx:    connCtx,
		connCancel: connCancel,
		engine:     eng,
	}
	cfg, err := l.buildTLS()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	l.tlsCfg = cfg
	return l, nil
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
			l.handle(l.connCtx, nc)
		}(c)
	}
}

func (l *Listener) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	if !l.engine.TryAcquire() {
		return
	}
	held := true
	release := func() {
		if held {
			l.engine.Release()
			held = false
		}
	}

	bound := &boundConn{Conn: nc}
	tlsConn := tls.Server(bound, l.tlsCfg)
	hs := l.opts.Settings.HandshakeTimeout
	if hs <= 0 {
		hs = 10 * time.Second
	}
	hsCtx, cancel := context.WithTimeout(ctx, hs)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		release()
		if l.opts.Logger != nil {
			l.opts.Logger.Info("secure reject: tls handshake failed")
		}
		return
	}
	if bound.identity.ClientID == "" {
		release()
		if l.opts.Logger != nil {
			l.opts.Logger.Info("secure reject: no client identity")
		}
		return
	}

	pio := newConn(tlsConn)
	held = false
	if err := l.engine.ServeHeld(ctx, pio, bound.identity); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		if l.opts.Logger != nil {
			l.opts.Logger.Debug("secure connection ended", "client_id", bound.identity.ClientID, "err", err)
		}
	}
}

// Shutdown stops accepts and waits for in-flight sessions up to ctx.
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

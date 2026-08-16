package tls

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

var _ runtime.Listener = (*Listener)(nil)

// Options construct a RADIUS/TLS (RadSec) listener.
type Options struct {
	ID         string
	Bind       string
	Required   bool
	Settings   config.RADIUSRadSecListener
	Grace      time.Duration
	Snapshot   func() *state.Snapshot
	Secrets    config.SecretLookup
	Access     server.Handler
	Accounting server.Handler
	Recorder   server.RADIUSRecorder
	Logger     *slog.Logger
	Metrics    *observability.Recorder
	Now        func() time.Time
	Listen     func(network, address string) (net.Listener, error)
}

// Listener is one RADIUS/TLS TCP+TLS 1.3 socket. Access and accounting
// share the connection; dynauth is not multiplexed.
type Listener struct {
	ln             net.Listener
	opts           Options
	tlsCfg         *tls.Config
	profiles       []tlsProfile
	defaultProfile tlsProfile
	requireSNI     bool
	clientCAFile   string
	crlPath        string
	access         server.Handler
	accounting     server.Handler
	cache          *cache
	journal        *journal
	sampler        *minuteSampler
	bounds         codec.Bounds

	ready     atomic.Bool
	closed    atomic.Bool
	inflight  atomic.Int64
	conns     atomic.Int64
	lastError atomic.Value // string

	connWG    sync.WaitGroup
	connMu    sync.Mutex
	active    map[net.Conn]struct{}
	maxConns  int
	idle      time.Duration
	handshake time.Duration
}

// Listen binds the TCP socket and prepares TLS. Serve runs the accept loop.
func Listen(opts Options) (*Listener, error) {
	if opts.Snapshot == nil {
		return nil, errors.New("snapshot accessor is required")
	}
	if opts.Secrets == nil {
		return nil, errors.New("secret lookup is required")
	}
	opts.Settings = normalizeRadSec(opts.Settings)
	if opts.Bind == "" {
		opts.Bind = opts.Settings.Bind
	}
	if opts.Bind == "" {
		return nil, errors.New("bind address is required")
	}
	if opts.ID == "" {
		opts.ID = runtime.IDRADIUSRadSec
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	access := opts.Access
	if access == nil {
		access = server.Stub{}
	}
	acct := opts.Accounting
	if acct == nil && opts.Recorder != nil {
		acct = server.Accounting{AAA: opts.Recorder}
	}
	if acct == nil {
		acct = server.Stub{}
	}
	listen := opts.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", opts.Bind)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		ln:         ln,
		opts:       opts,
		access:     access,
		accounting: acct,
		cache:      newCache(opts.Settings.RetransmissionCacheEntries, opts.Settings.RetransmissionCacheBytes, opts.Settings.RetransmissionTTL, opts.Now),
		journal:    newJournal(20000, 8<<20, 60*time.Second, opts.Now),
		sampler:    newMinuteSampler(60, opts.Now),
		bounds:     codec.Bounds{MaxPacketBytes: opts.Settings.MaxPacketBytes},
		active:     make(map[net.Conn]struct{}),
		maxConns:   opts.Settings.MaxConnections,
		idle:       opts.Settings.IdleTimeout,
		handshake:  opts.Settings.HandshakeTimeout,
	}
	cfg, err := l.buildTLS()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	l.tlsCfg = cfg
	return l, nil
}

func normalizeRadSec(s config.RADIUSRadSecListener) config.RADIUSRadSecListener {
	if s.MaxPacketBytes <= 0 {
		s.MaxPacketBytes = codec.MaxPacketBytes
	}
	if s.MaxConnections <= 0 {
		s.MaxConnections = 256
	}
	if s.IdleTimeout <= 0 {
		s.IdleTimeout = 60 * time.Second
	}
	if s.HandshakeTimeout <= 0 {
		s.HandshakeTimeout = 10 * time.Second
	}
	if s.RetransmissionCacheEntries <= 0 {
		s.RetransmissionCacheEntries = 10000
	}
	if s.RetransmissionCacheBytes <= 0 {
		s.RetransmissionCacheBytes = 4 << 20
	}
	if s.RetransmissionTTL <= 0 {
		s.RetransmissionTTL = 15 * time.Second
	}
	if s.Bind == "" {
		s.Bind = "0.0.0.0:2083"
	}
	if s.Transport == "" {
		s.Transport = config.EndpointTransportTLS
	}
	return s
}

// Addr is the bound TCP address (port may be ephemeral).
func (l *Listener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

func (l *Listener) track(c net.Conn) bool {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.maxConns > 0 && len(l.active) >= l.maxConns {
		return false
	}
	l.active[c] = struct{}{}
	l.conns.Store(int64(len(l.active)))
	return true
}

func (l *Listener) untrack(c net.Conn) {
	l.connMu.Lock()
	delete(l.active, c)
	l.conns.Store(int64(len(l.active)))
	l.connMu.Unlock()
}

func (l *Listener) closeActive() {
	l.connMu.Lock()
	conns := make([]net.Conn, 0, len(l.active))
	for c := range l.active {
		conns = append(conns, c)
	}
	l.connMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

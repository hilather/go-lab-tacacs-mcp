package udp

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

var _ runtime.Listener = (*Listener)(nil)

// Options construct a RADIUS/UDP listener for one role.
type Options struct {
	ID         string
	Role       domain.ListenerRole
	Bind       string
	Required   bool
	Settings   config.RADIUSListener
	Snapshot   func() *state.Snapshot
	Secrets    config.SecretLookup
	Handler    server.Handler
	Recorder   server.RADIUSRecorder
	Logger     *slog.Logger
	Metrics    *observability.Recorder
	Now        func() time.Time
	Listen     func(network, address string) (net.PacketConn, error)
	Challenges *radiusruntime.ChallengeStore // shared; Close must not Reset
}

type workItem struct {
	buf []byte
	src net.Addr
}

// Listener is one RADIUS/UDP PacketConn plus a bounded worker pool.
type Listener struct {
	pc         net.PacketConn
	opts       Options
	id         string
	role       domain.ListenerRole
	handler    server.Handler
	cache      *Cache
	journal    *journal
	sampler    *minuteSampler
	limit      *sourceLimiter
	queue      chan workItem
	bounds     codec.Bounds
	challenges *radiusruntime.ChallengeStore

	ready     atomic.Bool
	closed    atomic.Bool
	inflight  atomic.Int64
	queued    atomic.Int64
	lastError atomic.Value // string

	workerWG  sync.WaitGroup
	queueOnce sync.Once
}

// Listen binds the UDP socket and starts workers. Serve runs the receive loop.
func Listen(opts Options) (*Listener, error) {
	if opts.Snapshot == nil {
		return nil, errors.New("snapshot accessor is required")
	}
	if opts.Secrets == nil {
		return nil, errors.New("secret lookup is required")
	}
	switch opts.Role {
	case domain.RoleAccess, domain.RoleAccounting:
	default:
		return nil, errors.New("role must be access or accounting")
	}
	opts.Settings = normalizeSettings(opts.Settings, opts.Role)
	if opts.Bind == "" {
		opts.Bind = opts.Settings.Bind
	}
	if opts.Bind == "" {
		return nil, errors.New("bind address is required")
	}
	if opts.ID == "" {
		opts.ID = idForRole(opts.Role)
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	handler := opts.Handler
	if handler == nil && opts.Role == domain.RoleAccounting && opts.Recorder != nil {
		handler = server.Accounting{AAA: opts.Recorder}
	}
	if handler == nil {
		handler = server.Stub{}
	}
	listen := opts.Listen
	if listen == nil {
		listen = net.ListenPacket
	}
	pc, err := listen("udp", opts.Bind)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		pc:      pc,
		opts:    opts,
		id:      opts.ID,
		role:    opts.Role,
		handler: handler,
		cache:   newCache(opts.Settings.RetransmissionCacheEntries, opts.Settings.RetransmissionCacheBytes, opts.Settings.RetransmissionTTL, opts.Now),
		limit:   newSourceLimiter(opts.Settings.PerSourceRate, opts.Settings.PerSourceBurst, opts.Now),
		queue:   make(chan workItem, opts.Settings.QueueCapacity),
		bounds: codec.Bounds{
			MaxPacketBytes: opts.Settings.MaxPacketBytes,
		},
		challenges: opts.Challenges,
	}
	if opts.Role == domain.RoleAccounting {
		l.journal = newJournal(opts.Settings.JournalEntries, opts.Settings.JournalBytes, opts.Settings.RetransmissionTTL, opts.Now)
		l.sampler = newMinuteSampler(opts.Settings.AmbiguousAccountingPerMinute, opts.Now)
	}
	n := opts.Settings.Workers
	l.workerWG.Add(n)
	for i := 0; i < n; i++ {
		go l.worker()
	}
	return l, nil
}

func normalizeSettings(s config.RADIUSListener, role domain.ListenerRole) config.RADIUSListener {
	if s.MaxPacketBytes <= 0 {
		s.MaxPacketBytes = codec.MaxPacketBytes
	}
	if s.QueueCapacity <= 0 {
		s.QueueCapacity = 2048
	}
	if s.Workers <= 0 {
		if role == domain.RoleAccounting {
			s.Workers = 16
		} else {
			s.Workers = 32
		}
	}
	if s.WorkerDeadline <= 0 {
		s.WorkerDeadline = 5 * time.Second
	}
	if s.RetransmissionCacheEntries <= 0 {
		if role == domain.RoleAccounting {
			s.RetransmissionCacheEntries = 20000
		} else {
			s.RetransmissionCacheEntries = 10000
		}
	}
	if s.RetransmissionCacheBytes <= 0 {
		if role == domain.RoleAccounting {
			s.RetransmissionCacheBytes = 8 << 20
		} else {
			s.RetransmissionCacheBytes = 4 << 20
		}
	}
	if s.RetransmissionTTL <= 0 {
		if role == domain.RoleAccounting {
			s.RetransmissionTTL = 60 * time.Second
		} else {
			s.RetransmissionTTL = 15 * time.Second
		}
	}
	if s.PerSourceRate <= 0 {
		s.PerSourceRate = 100
	}
	if s.PerSourceBurst <= 0 {
		s.PerSourceBurst = 200
	}
	if role == domain.RoleAccounting {
		if s.JournalEntries <= 0 {
			s.JournalEntries = 20000
		}
		if s.JournalBytes <= 0 {
			s.JournalBytes = 8 << 20
		}
		if s.AmbiguousAccountingPerMinute < 0 {
			s.AmbiguousAccountingPerMinute = 60
		}
	}
	return s
}

func idForRole(role domain.ListenerRole) string {
	if role == domain.RoleAccounting {
		return runtime.IDRADIUSAccounting
	}
	return runtime.IDRADIUSAccess
}

// Addr is the bound UDP address (port may be ephemeral).
func (l *Listener) Addr() net.Addr {
	if l == nil || l.pc == nil {
		return nil
	}
	return l.pc.LocalAddr()
}

func (l *Listener) closeConn() {
	l.closed.Store(true)
	if l.pc != nil {
		_ = l.pc.Close()
	}
}

func (l *Listener) closeQueue() {
	l.queueOnce.Do(func() { close(l.queue) })
}

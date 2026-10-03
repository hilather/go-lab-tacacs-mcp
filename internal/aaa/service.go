package aaa

import (
	"sync"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Service is the protocol-independent AAA implementation.
type Service struct {
	mgr            *state.Manager
	snapshot       func() *state.Snapshot
	secrets        config.SecretLookup
	events         *events.Ring
	creds          *credentials.Service
	clock          domain.Clock
	metrics        *observability.Recorder
	radiusSessions *radiusruntime.SessionIndex

	mu       sync.Mutex
	sessions map[sessionKey]*authSession
}

type sessionKey struct {
	conn uint64
	sess uint32
}

type authFlow byte

const (
	flowASCII authFlow = iota
	flowEnable
	flowCHPASS
)

type authSession struct {
	flow        authFlow
	user        string
	clientID    string
	needUser    bool
	needOld     bool
	needNew     bool
	needConfirm bool
	newPass     []byte
	fails       int
	snap        *state.Snapshot
	creds       *credentials.Service
	maxRounds   int
	rev         domain.Revision
}

// Options construct a Service.
type Options struct {
	Manager  *state.Manager
	Snapshot func() *state.Snapshot
	Secrets  config.SecretLookup
	Events   *events.Ring
	Clock    domain.Clock
	Creds    credentials.Options
	Metrics  *observability.Recorder
	// Sessions is the in-memory RADIUS CoA index. Optional. Wiped on reset.
	Sessions *radiusruntime.SessionIndex
}

// New builds a Service. Snapshot or Manager is required.
func New(opts Options) (*Service, error) {
	if opts.Snapshot == nil && opts.Manager != nil {
		opts.Snapshot = opts.Manager.Snapshot
	}
	if opts.Snapshot == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "snapshot func is required")
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	if opts.Events == nil {
		opts.Events = events.New(0, opts.Clock)
	}
	opts.Creds.Clock = opts.Clock
	creds, err := credentials.NewService(snapshotStore{snapshot: opts.Snapshot, secrets: opts.Secrets}, opts.Creds)
	if err != nil {
		return nil, err
	}
	return &Service{
		mgr:            opts.Manager,
		snapshot:       opts.Snapshot,
		secrets:        opts.Secrets,
		events:         opts.Events,
		creds:          creds,
		clock:          opts.Clock,
		metrics:        opts.Metrics,
		radiusSessions: opts.Sessions,
		sessions:       map[sessionKey]*authSession{},
	}, nil
}

// RADIUSSessions is the CoA session index, if configured.
func (s *Service) RADIUSSessions() *radiusruntime.SessionIndex {
	if s == nil {
		return nil
	}
	return s.radiusSessions
}

// Events returns the ring used as the accounting sink.
func (s *Service) Events() *events.Ring {
	if s == nil {
		return nil
	}
	return s.events
}

func (s *Service) snap() *state.Snapshot {
	if s == nil || s.snapshot == nil {
		return nil
	}
	return s.snapshot()
}

func (s *Service) engine(snap *state.Snapshot) (*policy.Engine, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	e := snap.TACACSPolicies()
	if e == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "policy engine is not compiled")
	}
	return e, nil
}

// CompileSnapshot returns the evaluator compiled before snapshot publication.
// Kept for the shared diagnostic operation; it never compiles on a request.
func CompileSnapshot(snap *state.Snapshot) (*policy.Engine, error) {
	if snap == nil || snap.TACACSPolicies() == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "policy engine is not compiled")
	}
	return snap.TACACSPolicies(), nil
}

func (s *Service) record(e events.Event, _ bool) events.Event {
	if s == nil || s.events == nil {
		return events.Event{}
	}
	// UserID and command stay in the ring so events:sensitive can unredact.
	// Stdout JSON and events.list redact unless the caller has that scope.
	return s.events.Accept(e)
}

func includeAuthorization(snap *state.Snapshot) bool {
	if snap == nil || snap.Settings() == nil {
		return true
	}
	return snap.Settings().Events.IncludeAuthorization
}

func includeAccounting(snap *state.Snapshot) bool {
	if snap == nil || snap.Settings() == nil {
		return true
	}
	return snap.Settings().Events.IncludeAccounting
}

func maxRounds(snap *state.Snapshot) int {
	if snap == nil || snap.Settings() == nil || snap.Settings().Limits.MaxAuthenticationRounds <= 0 {
		return 3
	}
	return snap.Settings().Limits.MaxAuthenticationRounds
}

func (s *Service) getSession(key sessionKey) *authSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *Service) putSession(key sessionKey, sess *authSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = sess
}

func (s *Service) dropSession(key sessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessions[key]; sess != nil {
		wipe(sess.newPass)
		sess.newPass = nil
	}
	delete(s.sessions, key)
}

// InFlight is the number of in-progress authentication conversations.
func (s *Service) InFlight() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

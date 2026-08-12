package aaa

import (
	"sync"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/policy"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Service is the protocol-independent AAA implementation.
type Service struct {
	snapshot func() *state.Snapshot
	secrets  config.SecretLookup
	events   *events.Ring
	creds    *credentials.Service
	clock    domain.Clock

	mu       sync.Mutex
	sessions map[sessionKey]*asciiSession
	engines  map[domain.Revision]*policy.Engine
}

type sessionKey struct {
	conn uint64
	sess uint32
}

type asciiSession struct {
	user     string
	clientID string
	needUser bool
	needPass bool
	fails    int
}

// Options construct a Service.
type Options struct {
	Snapshot func() *state.Snapshot
	Secrets  config.SecretLookup
	Events   *events.Ring
	Clock    domain.Clock
	Creds    credentials.Options
}

// New builds a Service. Snapshot is required.
func New(opts Options) (*Service, error) {
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
		snapshot: opts.Snapshot,
		secrets:  opts.Secrets,
		events:   opts.Events,
		creds:    creds,
		clock:    opts.Clock,
		sessions: map[sessionKey]*asciiSession{},
		engines:  map[domain.Revision]*policy.Engine{},
	}, nil
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
	s.mu.Lock()
	if e, ok := s.engines[snap.Revision]; ok {
		s.mu.Unlock()
		return e, nil
	}
	s.mu.Unlock()
	e, err := CompileSnapshot(snap)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.engines[snap.Revision] = e
	s.mu.Unlock()
	return e, nil
}

// CompileSnapshot builds the two policy evaluators from the effective snapshot.
func CompileSnapshot(snap *state.Snapshot) (*policy.Engine, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	users := make([]config.User, 0, len(snap.Users()))
	for _, u := range snap.Users() {
		users = append(users, u.User)
	}
	groups := make([]config.Group, 0, len(snap.Groups()))
	for _, g := range snap.Groups() {
		groups = append(groups, g.Group)
	}
	clients := make([]config.Client, 0, len(snap.Clients()))
	for _, c := range snap.Clients() {
		clients = append(clients, c.Client)
	}
	limits := config.Limits{}
	if settings := snap.Settings(); settings != nil {
		limits = settings.Limits
	}
	return policy.Compile(policy.Input{
		Users:    users,
		Groups:   groups,
		Clients:  clients,
		Fallback: snap.FallbackRules(),
		Limits:   limits,
	})
}

func (s *Service) record(e events.Event, redact bool) events.Event {
	if s == nil || s.events == nil {
		return events.Event{}
	}
	if redact {
		e.UserID = ""
		e.Command = ""
	}
	return s.events.Accept(e)
}

func redactUserInput(snap *state.Snapshot) bool {
	if snap == nil || snap.Settings() == nil {
		return true
	}
	return snap.Settings().Events.RedactUserInput
}

func maxRounds(snap *state.Snapshot) int {
	if snap == nil || snap.Settings() == nil || snap.Settings().Limits.MaxAuthenticationRounds <= 0 {
		return 3
	}
	return snap.Settings().Limits.MaxAuthenticationRounds
}

func (s *Service) getSession(key sessionKey) *asciiSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *Service) putSession(key sessionKey, sess *asciiSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = sess
}

func (s *Service) dropSession(key sessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
}

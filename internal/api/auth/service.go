package auth

import (
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	// CookieName is the HttpOnly session cookie.
	CookieName = "taclab_session"
	// CSRFCookieName is the non-HttpOnly double-submit cookie.
	CSRFCookieName = "taclab_csrf"
	// CSRFHeader is the mutation header that must match the issued CSRF token.
	CSRFHeader = "X-CSRF-Token"
	// BearerRealm is the courtesy WWW-Authenticate challenge. 1.0 does not
	// serve OAuth protected-resource metadata (ADR 0010).
	BearerRealm = `Bearer realm="taclab"`

	defaultSessionCap = 10000
	lastUsedGrain     = time.Minute
)

// Options configure clocks, entropy, and session bounds.
type Options struct {
	Clock    domain.Clock
	Entropy  domain.Entropy
	MaxSess  int
	ReadOpts config.ReadOptions
}

// Service verifies bearers against a published snapshot, tracks coarse
// last-used times, and issues UI sessions. It is safe for concurrent use.
type Service struct {
	clock    domain.Clock
	entropy  io.Reader
	maxSess  int
	readOpts config.ReadOptions

	mu       sync.Mutex
	sessions map[string]sessionRec
	lastUsed map[string]time.Time
}

type sessionRec struct {
	id         string
	tokenID    string
	scopes     []string
	cookieHash credentials.TokenDigest
	csrfHash   credentials.TokenDigest
	created    time.Time
	lastSeen   time.Time
}

// New returns a Service. Zero Options select production clock and entropy.
func New(opts Options) *Service {
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	if opts.Entropy == nil {
		opts.Entropy = rand.Reader
	}
	if opts.MaxSess <= 0 {
		opts.MaxSess = defaultSessionCap
	}
	return &Service{
		clock:    opts.Clock,
		entropy:  opts.Entropy,
		maxSess:  opts.MaxSess,
		readOpts: opts.ReadOpts,
		sessions: map[string]sessionRec{},
		lastUsed: map[string]time.Time{},
	}
}

// Principal is an authenticated token or UI session.
type Principal struct {
	TokenID   string
	Scopes    []string
	SessionID string
	Cookie    bool
}

// Actor converts p to the operation-layer principal.
func (p Principal) Actor() operations.Actor {
	return operations.Actor{
		ID:        p.TokenID,
		Scopes:    append([]string(nil), p.Scopes...),
		SessionID: p.SessionID,
	}
}

// Request is adapter-facing authentication input. Authorization is the raw
// HTTP header value. Cookie is the session cookie value only.
type Request struct {
	Authorization string
	Cookie        string
	CSRF          string
	Mutating      bool
}

// Authenticate verifies a bearer or a UI session. Cookie-authenticated
// mutations require a matching CSRF token whenever UI sessions are enabled.
func (s *Service) Authenticate(req Request, snap *state.Snapshot) (Principal, error) {
	if bearer, ok := parseBearer(req.Authorization); ok {
		return s.VerifyBearer(bearer, snap)
	}
	if strings.TrimSpace(req.Cookie) != "" {
		return s.VerifyCookie(req.Cookie, req.CSRF, req.Mutating, snap)
	}
	return Principal{}, unauthenticated()
}

// VerifyBearer authenticates raw token bytes against the snapshot index.
func (s *Service) VerifyBearer(raw []byte, snap *state.Snapshot) (Principal, error) {
	if snap == nil {
		return Principal{}, unauthenticated()
	}
	now := s.now()
	tok, err := snap.AuthenticateToken(raw, now)
	if err != nil {
		return Principal{}, err
	}
	s.Touch(tok.ID, now)
	return Principal{TokenID: tok.ID, Scopes: append([]string(nil), tok.Scopes...)}, nil
}

// VerifyCookie authenticates a session cookie. CSRF is required on mutations
// when api.ui_session.enabled is true.
func (s *Service) VerifyCookie(cookie, csrf string, mutating bool, snap *state.Snapshot) (Principal, error) {
	if s == nil || snap == nil {
		return Principal{}, unauthenticated()
	}
	cfg := uiSession(snap)
	if !cfg.Enabled {
		return Principal{}, unauthenticated()
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.lookupCookieLocked(cookie)
	if !ok {
		return Principal{}, unauthenticated()
	}
	if expired(rec, cfg, now) {
		delete(s.sessions, rec.id)
		return Principal{}, unauthenticated()
	}
	if mutating {
		if strings.TrimSpace(csrf) == "" || !credentials.EqualDigest(rec.csrfHash, credentials.DigestToken(credentials.NewTokenMaterial([]byte(csrf)))) {
			return Principal{}, domain.NewError(domain.CodePermissionDenied, "CSRF token required")
		}
	}
	tok, ok := snap.Token(rec.tokenID)
	if !ok || !tok.Enabled {
		delete(s.sessions, rec.id)
		return Principal{}, unauthenticated()
	}
	if tok.ExpiresAt != nil && !now.Before(tok.ExpiresAt.UTC()) {
		delete(s.sessions, rec.id)
		return Principal{}, unauthenticated()
	}
	rec.lastSeen = now
	s.sessions[rec.id] = rec
	s.touchLocked(rec.tokenID, now)
	return Principal{
		TokenID:   rec.tokenID,
		Scopes:    append([]string(nil), tok.Scopes...),
		SessionID: rec.id,
		Cookie:    true,
	}, nil
}

// Create implements operations.SessionService.
func (s *Service) Create(actor operations.Actor, snap *state.Snapshot) (operations.Session, error) {
	if actor.ID == "" {
		return operations.Session{}, unauthenticated()
	}
	if snap == nil {
		return operations.Session{}, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	cfg := uiSession(snap)
	if !cfg.Enabled {
		return operations.Session{}, domain.NewError(domain.CodeInvalidArgument, "UI sessions are disabled")
	}
	if strings.EqualFold(cfg.CookieSameSite, "none") && !cfg.CookieSecure {
		return operations.Session{}, domain.NewError(domain.CodeInvalidArgument, "cookie_same_site none requires cookie_secure")
	}
	now := s.now()
	tok, ok := snap.Token(actor.ID)
	if !ok || !tok.Enabled {
		return operations.Session{}, unauthenticated()
	}
	if tok.ExpiresAt != nil && !now.Before(tok.ExpiresAt.UTC()) {
		return operations.Session{}, unauthenticated()
	}
	cookieVal, cookieHash, err := issueSecret(s.entropy)
	if err != nil {
		return operations.Session{}, domain.NewError(domain.CodeInternal, "cannot issue session")
	}
	csrfVal, csrfHash, err := issueSecret(s.entropy)
	if err != nil {
		return operations.Session{}, domain.NewError(domain.CodeInternal, "cannot issue CSRF token")
	}
	id, err := randomID(s.entropy)
	if err != nil {
		return operations.Session{}, domain.NewError(domain.CodeInternal, "cannot issue session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.maxSess {
		return operations.Session{}, domain.NewError(domain.CodeUnavailable, "session capacity exceeded")
	}
	s.sessions[id] = sessionRec{
		id:         id,
		tokenID:    actor.ID,
		scopes:     append([]string(nil), tok.Scopes...),
		cookieHash: cookieHash,
		csrfHash:   csrfHash,
		created:    now,
		lastSeen:   now,
	}
	lifetime := cfg.Lifetime
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	return operations.Session{
		TokenID:      actor.ID,
		Scopes:       append([]string(nil), tok.Scopes...),
		ExpiresAt:    now.Add(lifetime),
		CSRFToken:    csrfVal,
		CookieName:   CookieName,
		CookieSecure: cfg.CookieSecure,
		SameSite:     sameSiteName(cfg.CookieSameSite),
		CookiePath:   "/",
		CookieMaxAge: int(lifetime.Seconds()),
		Revision:     snap.Revision,
		Cookie:       credentials.NewSessionCookie([]byte(cookieVal)),
	}, nil
}

// Delete implements operations.SessionService.
func (s *Service) Delete(sessionID string) (operations.DeleteResult, error) {
	if s == nil || sessionID == "" {
		return operations.DeleteResult{}, domain.NewError(domain.CodeNotFound, "session not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sessionID]; !ok {
		return operations.DeleteResult{}, domain.NewError(domain.CodeNotFound, "session not found")
	}
	delete(s.sessions, sessionID)
	return operations.DeleteResult{ID: sessionID}, nil
}

// SessionCookie builds the HttpOnly session Set-Cookie attributes.
func SessionCookie(sess operations.Session) *http.Cookie {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    string(sess.Cookie.Bytes()),
		Path:     sess.CookiePath,
		MaxAge:   sess.CookieMaxAge,
		HttpOnly: true,
		Secure:   sess.CookieSecure,
		SameSite: sameSiteMode(sess.SameSite),
	}
	if c.Path == "" {
		c.Path = "/"
	}
	return c
}

// CSRFSetCookie builds the non-HttpOnly CSRF cookie for double-submit.
func CSRFSetCookie(sess operations.Session) *http.Cookie {
	return &http.Cookie{
		Name:     CSRFCookieName,
		Value:    sess.CSRFToken,
		Path:     "/",
		MaxAge:   sess.CookieMaxAge,
		HttpOnly: false,
		Secure:   sess.CookieSecure,
		SameSite: sameSiteMode(sess.SameSite),
	}
}

// Touch records coarse last-used time for a token id.
func (s *Service) Touch(id string, now time.Time) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	s.touchLocked(id, now)
	s.mu.Unlock()
}

// LastUsed returns the coarse last-used timestamp when present.
func (s *Service) LastUsed(id string) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.lastUsed[id]
	return ts, ok
}

func (s *Service) touchLocked(id string, now time.Time) {
	if id == "" {
		return
	}
	if s.lastUsed == nil {
		s.lastUsed = map[string]time.Time{}
	}
	s.lastUsed[id] = now.UTC().Truncate(lastUsedGrain)
}

func (s *Service) lookupCookieLocked(cookie string) (sessionRec, bool) {
	presented := credentials.DigestToken(credentials.NewTokenMaterial([]byte(cookie)))
	for _, rec := range s.sessions {
		if credentials.EqualDigest(rec.cookieHash, presented) {
			return rec, true
		}
	}
	return sessionRec{}, false
}

func (s *Service) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

func expired(rec sessionRec, cfg config.UISession, now time.Time) bool {
	if cfg.Lifetime > 0 && !now.Before(rec.created.Add(cfg.Lifetime)) {
		return true
	}
	if cfg.IdleTimeout > 0 && !now.Before(rec.lastSeen.Add(cfg.IdleTimeout)) {
		return true
	}
	return false
}

func uiSession(snap *state.Snapshot) config.UISession {
	if snap == nil || snap.Settings() == nil {
		return config.UISession{}
	}
	return snap.Settings().API.UISession
}

func unauthenticated() error {
	return domain.NewError(domain.CodeUnauthenticated, "authentication required")
}

func sameSiteName(s string) string {
	switch strings.ToLower(s) {
	case "lax":
		return "lax"
	case "none":
		return "none"
	default:
		return "strict"
	}
}

func sameSiteMode(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

func issueSecret(entropy io.Reader) (string, credentials.TokenDigest, error) {
	return credentials.IssueBearer(entropy)
}

func randomID(entropy io.Reader) (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(entropy, b); err != nil {
		return "", err
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 16)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out), nil
}

func parseBearer(h string) ([]byte, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil, false
	}
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return nil, false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return nil, false
	}
	return []byte(tok), true
}

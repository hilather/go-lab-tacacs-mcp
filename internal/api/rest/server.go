package rest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	defaultMaxBody    = 2 << 20
	defaultInFlight   = 256
	headerRequestID   = "X-Request-ID"
	headerETag        = "ETag"
	headerIfMatch     = "If-Match"
	headerIdempotency = "Idempotency-Key"
	revisionPrefix    = "revision-"
)

// FrozenREST is the PR-16a route set: implemented operation handlers plus
// REST_ONLY health and OpenAPI. Unimplemented registry ops are not bound.
var FrozenREST = []string{
	operations.IDSystemStatusGet,
	operations.IDSystemBuildGet,
	operations.IDPolicyEvaluate,
	operations.IDTokensList,
	operations.IDTokensCreate,
	operations.IDTokensRevoke,
	operations.IDSessionCreate,
	operations.IDSessionDelete,
	operations.IDEventsList,
	operations.IDEventsSubscribe,
}

// Server is the versioned REST adapter.
type Server struct {
	Registry     *operations.Registry
	Snapshot     func() *state.Snapshot
	Auth         *auth.Service
	Events       *events.Ring
	Ready        func() bool
	MaxBody      int64
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	MaxInFlight  int
	Logger       *slog.Logger

	once     sync.Once
	limiter  *limiter
	inflight chan struct{}
}

type envelope struct {
	Revision  uint64 `json:"revision"`
	RequestID string `json:"request_id"`
	Data      any    `json:"data"`
}

type ctxKey int

const requestIDKey ctxKey = 1

// Handler returns the mux for health and the frozen /api/v1 routes.
func (s *Server) Handler() http.Handler {
	s.once.Do(s.init)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /api/openapi.json", s.openapi)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/build", s.build)
	mux.HandleFunc("POST /api/v1/policy/evaluate", s.evaluate)
	mux.HandleFunc("GET /api/v1/events", s.listEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.streamEvents)
	mux.HandleFunc("GET /api/v1/tokens", s.listTokens)
	mux.HandleFunc("POST /api/v1/tokens", s.createToken)
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.revokeToken)
	mux.HandleFunc("POST /api/v1/session", s.createSession)
	mux.HandleFunc("DELETE /api/v1/session", s.deleteSessionClear)
	return s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
}

func (s *Server) init() {
	if s.limiter == nil {
		s.limiter = newLimiter()
	}
	n := s.MaxInFlight
	if n <= 0 {
		n = defaultInFlight
	}
	s.inflight = make(chan struct{}, n)
}

func (s *Server) maxBody() int64 {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return defaultMaxBody
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	if s.Ready != nil && !s.Ready() {
		writeProblem(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "not ready"))
		return
	}
	if s.Snapshot == nil || s.Snapshot() == nil {
		writeProblem(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "not ready"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	s.invoke(w, r, operations.IDSystemStatusGet, operations.GetStatusRequest{}, false)
}

func (s *Server) build(w http.ResponseWriter, r *http.Request) {
	s.invoke(w, r, operations.IDSystemBuildGet, operations.GetBuildRequest{}, false)
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	var req operations.EvaluatePolicyRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDPolicyEvaluate, req, false)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := operations.ListEventsRequest{
		Cursor:     q.Get("cursor"),
		Categories: q["category"],
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeProblemID(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "invalid limit"), requestIDFrom(r))
			return
		}
		req.Limit = n
	}
	s.invoke(w, r, operations.IDEventsList, req, false)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := operations.ListTokensRequest{Cursor: q.Get("cursor")}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeProblemID(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "invalid limit"), requestIDFrom(r))
			return
		}
		req.Limit = n
	}
	s.invoke(w, r, operations.IDTokensList, req, false)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var req operations.CreateTokenRequest
	if err := decodeJSON(r, &req, s.maxBody()); err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDTokensCreate, req, true)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	req := operations.RevokeTokenRequest{ID: r.PathValue("id")}
	if raw := r.URL.Query().Get("tombstone"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			writeProblemID(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "invalid tombstone"), requestIDFrom(r))
			return
		}
		req.Tombstone = v
	}
	s.invoke(w, r, operations.IDTokensRevoke, req, true)
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request, id string, req any, mutating bool) {
	rid := requestIDFrom(r)
	if s.Registry == nil {
		writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"), rid)
		return
	}
	actor, snap, err := s.authenticate(r, mutating)
	if err != nil {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			writeDomainID(w, lerr, rid)
			return
		}
		writeDomainID(w, err, rid)
		return
	}
	if err := s.limit(actor, snap); err != nil {
		writeDomainID(w, err, rid)
		return
	}
	rev, err := parseIfMatch(r.Header.Get(headerIfMatch))
	if err != nil {
		writeDomainID(w, err, rid)
		return
	}
	res, err := s.Registry.Invoke(r.Context(), id, snap, operations.Input{
		Actor:            actor,
		ExpectedRevision: rev,
		IdempotencyKey:   strings.TrimSpace(r.Header.Get(headerIdempotency)),
		Request:          req,
	})
	if err != nil {
		writeDomainID(w, err, rid)
		return
	}
	w.Header().Set(headerETag, etag(res.Revision))
	writeJSON(w, http.StatusOK, envelope{Revision: uint64(res.Revision), RequestID: rid, Data: res.Data})
}

func (s *Server) authenticate(r *http.Request, mutating bool) (operations.Actor, *state.Snapshot, error) {
	if s.Auth == nil {
		return operations.Actor{}, nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	snap := (*state.Snapshot)(nil)
	if s.Snapshot != nil {
		snap = s.Snapshot()
	}
	cookie := ""
	if c, err := r.Cookie(auth.CookieName); err == nil {
		cookie = c.Value
	}
	csrf := strings.TrimSpace(r.Header.Get(auth.CSRFHeader))
	if csrf == "" {
		if c, err := r.Cookie(auth.CSRFCookieName); err == nil {
			csrf = c.Value
		}
	}
	p, err := s.Auth.Authenticate(auth.Request{
		Authorization: r.Header.Get("Authorization"),
		Cookie:        cookie,
		CSRF:          csrf,
		Mutating:      mutating,
	}, snap)
	if err != nil {
		return operations.Actor{}, snap, err
	}
	return p.Actor(), snap, nil
}

func (s *Server) limit(actor operations.Actor, snap *state.Snapshot) error {
	if s.limiter == nil {
		return nil
	}
	cfg := rateConfig(snap)
	if !cfg.Enabled {
		return nil
	}
	key := actor.ID
	rate := cfg.PerTokenRequestsPerSecond
	burst := cfg.PerTokenBurst
	if key == "" {
		key = "unauthenticated"
		rate = cfg.UnauthenticatedRequestsPerSecond
		burst = cfg.UnauthenticatedBurst
	}
	if !s.limiter.allow(key, rate, burst, time.Now()) {
		return domain.NewError(domain.CodeRateLimited, "rate limit exceeded")
	}
	return nil
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

func requestIDFrom(r *http.Request) string {
	if r == nil {
		return newRequestID()
	}
	if v, ok := r.Context().Value(requestIDKey).(string); ok && v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get(headerRequestID)); v != "" {
		return v
	}
	return newRequestID()
}

func parseIfMatch(h string) (*domain.Revision, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil, nil
	}
	h = strings.Trim(h, `"`)
	if !strings.HasPrefix(h, revisionPrefix) {
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid If-Match")
	}
	n, err := strconv.ParseUint(h[len(revisionPrefix):], 10, 64)
	if err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid If-Match")
	}
	rev := domain.Revision(n)
	return &rev, nil
}

func etag(rev domain.Revision) string {
	return `"` + revisionPrefix + strconv.FormatUint(uint64(rev), 10) + `"`
}

func decodeJSON(r *http.Request, dest any, max int64) error {
	if err := requireJSON(r); err != nil {
		return err
	}
	if r.Body == nil {
		return domain.NewError(domain.CodeInvalidArgument, "invalid request body")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return domain.NewError(domain.CodeInvalidArgument, "invalid request body")
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return domain.NewError(domain.CodeInvalidArgument, "invalid request body")
	}
	return nil
}

func requireJSON(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		if r.ContentLength == 0 || r.Body == nil || r.Body == http.NoBody {
			return nil
		}
		return domain.NewError(domain.CodeInvalidArgument, "Content-Type must be application/json")
	}
	media, _, err := mime.ParseMediaType(ct)
	if err != nil || media != "application/json" {
		return domain.NewError(domain.CodeInvalidArgument, "Content-Type must be application/json")
	}
	return nil
}

func rateConfig(snap *state.Snapshot) config.RateLimits {
	if snap == nil || snap.Settings() == nil {
		return config.RateLimits{
			Enabled:                          true,
			PerTokenRequestsPerSecond:        50,
			PerTokenBurst:                    100,
			UnauthenticatedRequestsPerSecond: 5,
			UnauthenticatedBurst:             10,
		}
	}
	return snap.Settings().API.RateLimits
}

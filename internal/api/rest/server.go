package rest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
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
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/ui"
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

// FrozenREST is the implemented REST operation set plus REST_ONLY health
// and OpenAPI. MCP-only registry rows are not bound.
var FrozenREST = []string{
	operations.IDSystemStatusGet,
	operations.IDSystemBuildGet,
	operations.IDConfigEffectiveGet,
	operations.IDConfigValidate,
	operations.IDConfigReload,
	operations.IDConfigExport,
	operations.IDRuntimeReset,
	operations.IDUsersList,
	operations.IDUsersGet,
	operations.IDUsersCreate,
	operations.IDUsersUpdate,
	operations.IDUsersDelete,
	operations.IDGroupsList,
	operations.IDGroupsGet,
	operations.IDGroupsCreate,
	operations.IDGroupsUpdate,
	operations.IDGroupsDelete,
	operations.IDClientsList,
	operations.IDClientsGet,
	operations.IDClientsCreate,
	operations.IDClientsUpdate,
	operations.IDClientsDelete,
	operations.IDPolicyEvaluate,
	operations.IDAuthenticationTest,
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
	SSEBuffer    int
	Logger       *slog.Logger
	// Assets is the SPA tree. Nil uses the embedded UI (stub or production copy).
	Assets  fs.FS
	Metrics *observability.Recorder
	Tracer  *observability.Tracer

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

// Handler returns the mux for health and the /api/v1 routes.
func (s *Server) Handler() http.Handler {
	s.once.Do(s.init)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /api/openapi.json", s.openapi)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/build", s.build)
	mux.HandleFunc("GET /api/v1/config/effective", s.effectiveConfig)
	mux.HandleFunc("POST /api/v1/config/validate", s.validateConfig)
	mux.HandleFunc("POST /api/v1/config/reload", s.reloadConfig)
	mux.HandleFunc("GET /api/v1/config/export", s.exportConfig)
	mux.HandleFunc("POST /api/v1/runtime/reset", s.resetRuntime)
	mux.HandleFunc("GET /api/v1/users", s.listUsers)
	mux.HandleFunc("POST /api/v1/users", s.createUser)
	mux.HandleFunc("GET /api/v1/users/{id}", s.getUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.updateUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.deleteUser)
	mux.HandleFunc("GET /api/v1/groups", s.listGroups)
	mux.HandleFunc("POST /api/v1/groups", s.createGroup)
	mux.HandleFunc("GET /api/v1/groups/{id}", s.getGroup)
	mux.HandleFunc("PATCH /api/v1/groups/{id}", s.updateGroup)
	mux.HandleFunc("DELETE /api/v1/groups/{id}", s.deleteGroup)
	mux.HandleFunc("GET /api/v1/clients", s.listClients)
	mux.HandleFunc("POST /api/v1/clients", s.createClient)
	mux.HandleFunc("GET /api/v1/clients/{id}", s.getClient)
	mux.HandleFunc("PATCH /api/v1/clients/{id}", s.updateClient)
	mux.HandleFunc("DELETE /api/v1/clients/{id}", s.deleteClient)
	mux.HandleFunc("POST /api/v1/policy/evaluate", s.evaluate)
	mux.HandleFunc("POST /api/v1/authentication/test", s.testAuthentication)
	mux.HandleFunc("GET /api/v1/events", s.listEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.streamEvents)
	mux.HandleFunc("GET /api/v1/tokens", s.listTokens)
	mux.HandleFunc("POST /api/v1/tokens", s.createToken)
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.revokeToken)
	mux.HandleFunc("POST /api/v1/session", s.createSession)
	mux.HandleFunc("DELETE /api/v1/session", s.deleteSessionClear)
	mux.Handle("/{$}", s.ui())
	mux.Handle("/{path...}", s.ui())
	return s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
}

func (s *Server) ui() http.Handler {
	fsys := s.Assets
	if fsys == nil {
		fsys = ui.Files()
	}
	return ui.NewHandler(fsys)
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
	req, err := listEventsRequest(r.URL.Query())
	if err != nil {
		writeDomainID(w, err, requestIDFrom(r))
		return
	}
	s.invoke(w, r, operations.IDEventsList, req, false)
}

func listEventsRequest(q map[string][]string) (operations.ListEventsRequest, error) {
	req := operations.ListEventsRequest{
		Cursor:       firstQuery(q, "cursor"),
		Categories:   q["category"],
		Protocol:     firstQuery(q, "protocol"),
		ListenerRole: firstQuery(q, "listener_role"),
		PacketCode:   firstQuery(q, "packet_code"),
		Outcome:      firstQuery(q, "outcome"),
	}
	if raw := firstQuery(q, "limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return req, domain.NewError(domain.CodeInvalidArgument, "invalid limit")
		}
		req.Limit = n
	}
	return req, nil
}

func firstQuery(q map[string][]string, key string) string {
	vals := q[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
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
	start := time.Now()
	rid := requestIDFrom(r)
	ctx, span := s.Tracer.Start(r.Context(), "rest."+id, observability.Attr{Key: "operation_id", Value: id}, observability.Attr{Key: "request_id", Value: rid})
	defer span.End()
	if s.Registry == nil {
		s.observeAPI(id, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"), start)
		writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"), rid)
		return
	}
	actor, snap, err := s.authenticate(r, mutating)
	if err != nil {
		if lerr := s.limit(operations.Actor{}, snap); lerr != nil {
			s.observeAPI(id, lerr, start)
			writeDomainID(w, lerr, rid)
			return
		}
		s.observeAPI(id, err, start)
		writeDomainID(w, err, rid)
		return
	}
	if err := s.limit(actor, snap); err != nil {
		s.observeAPI(id, err, start)
		writeDomainID(w, err, rid)
		return
	}
	rev, err := parseIfMatch(r.Header.Get(headerIfMatch))
	if err != nil {
		s.observeAPI(id, err, start)
		writeDomainID(w, err, rid)
		return
	}
	res, err := s.Registry.Invoke(ctx, id, snap, operations.Input{
		Actor:            actor,
		ExpectedRevision: rev,
		IdempotencyKey:   strings.TrimSpace(r.Header.Get(headerIdempotency)),
		Request:          req,
	})
	if err != nil {
		s.observeAPI(id, err, start)
		writeDomainID(w, err, rid)
		return
	}
	s.observeAPI(id, nil, start)
	w.Header().Set(headerETag, etag(res.Revision))
	writeJSON(w, http.StatusOK, envelope{Revision: uint64(res.Revision), RequestID: rid, Data: res.Data})
}

func (s *Server) observeAPI(id string, err error, start time.Time) {
	result, code := observability.ResultFromError(err)
	s.Metrics.API(id, result, code, time.Since(start).Seconds())
	if id == operations.IDConfigReload {
		s.Metrics.Reload(err == nil)
	}
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
	// CSRF must come from the header (or a form field). Never treat the
	// taclab_csrf cookie as the presented token: browsers send it automatically.
	csrf := strings.TrimSpace(r.Header.Get(auth.CSRFHeader))
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

// decodeOptionalJSON decodes a JSON object when a body is present. Empty
// bodies, including HTTP/2 ContentLength=-1 with immediate EOF, are success.
func decodeOptionalJSON(r *http.Request, dest any, max int64) error {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return nil
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" && r.ContentLength < 0 {
		return nil
	}
	if err := requireJSON(r); err != nil {
		return err
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		if err == io.EOF {
			return nil
		}
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

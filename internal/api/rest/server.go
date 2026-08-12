package rest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Server is the versioned REST adapter.
type Server struct {
	Registry *operations.Registry
	Snapshot func() *state.Snapshot
	Auth     *auth.Verifier
	Ready    func() bool
	MaxBody  int64
}

const defaultMaxBody = 2 << 20

// Handler returns the mux for health and the implemented /api/v1 routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("POST /api/v1/policy/evaluate", s.evaluate)
	mux.HandleFunc("GET /api/v1/events", s.listEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.eventsStub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MaxBody > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.MaxBody)
		} else if s.MaxBody == 0 {
			r.Body = http.MaxBytesReader(w, r.Body, defaultMaxBody)
		}
		mux.ServeHTTP(w, r)
	})
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
	s.invoke(w, r, operations.IDSystemStatusGet, operations.GetStatusRequest{})
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
			writeProblem(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "invalid limit"))
			return
		}
		req.Limit = n
	}
	s.invoke(w, r, operations.IDEventsList, req)
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	var req operations.EvaluatePolicyRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, s.maxBody()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "invalid request body"))
		return
	}
	s.invoke(w, r, operations.IDPolicyEvaluate, req)
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request, id string, req any) {
	if s.Registry == nil {
		writeProblem(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized"))
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		writeDomain(w, err)
		return
	}
	snap := (*state.Snapshot)(nil)
	if s.Snapshot != nil {
		snap = s.Snapshot()
	}
	res, err := s.Registry.Invoke(r.Context(), id, snap, operations.Input{Actor: actor, Request: req})
	if err != nil {
		writeDomain(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{Revision: uint64(res.Revision), RequestID: newRequestID(), Data: res.Data})
}

func (s *Server) actor(r *http.Request) (operations.Actor, error) {
	raw, ok := auth.ParseBearer(r.Header.Get("Authorization"))
	if !ok {
		return operations.Actor{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	if s.Auth == nil {
		return operations.Actor{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	p, err := s.Auth.Authenticate(raw)
	if err != nil {
		return operations.Actor{}, err
	}
	return p.Actor(), nil
}

func (s *Server) maxBody() int64 {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return defaultMaxBody
}

type envelope struct {
	Revision  uint64 `json:"revision"`
	RequestID string `json:"request_id"`
	Data      any    `json:"data"`
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// ClearWriteDeadline drops the http.Server write deadline so long-lived
// SSE / listen responses are not killed by listeners.http.write_timeout.
func ClearWriteDeadline(w http.ResponseWriter) error {
	return http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func (s *Server) eventsStub(w http.ResponseWriter, r *http.Request) {
	if _, err := s.actor(r); err != nil {
		writeDomain(w, err)
		return
	}
	_ = ClearWriteDeadline(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, ": keepalive\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

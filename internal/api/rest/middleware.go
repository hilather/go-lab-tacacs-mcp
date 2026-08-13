package rest

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func (s *Server) wrap(next http.Handler) http.Handler {
	return s.withRecover(s.withRequestID(s.withHeaders(s.withInFlight(s.withBodyLimit(s.withAccessLog(next))))))
}

func (s *Server) withBodyLimit(next http.Handler) http.Handler {
	max := s.maxBody()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		if r.ContentLength > max {
			writeProblemID(w, http.StatusBadRequest, domain.NewError(domain.CodeInvalidArgument, "request body too large"), requestIDFrom(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(headerRequestID))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(headerRequestID, id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// CORS is disabled: no Access-Control-Allow-Origin.
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				if s.Logger != nil {
					s.Logger.Error("rest panic", "request_id", requestIDFrom(r), "err", "panic")
				}
				if !rw.wrote {
					writeProblemID(rw, http.StatusInternalServerError, domain.NewError(domain.CodeInternal, "internal error"), requestIDFrom(r))
				}
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw, _ := w.(*statusWriter)
		if rw == nil {
			rw = &statusWriter{ResponseWriter: w, status: http.StatusOK}
			w = rw
		}
		next.ServeHTTP(w, r)
		if s.Logger == nil {
			return
		}
		s.Logger.Info("rest",
			slog.String("request_id", requestIDFrom(r)),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.status),
			slog.Duration("dur", time.Since(start)),
		)
	})
}

func (s *Server) withInFlight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
			next.ServeHTTP(w, r)
		default:
			writeProblemID(w, http.StatusServiceUnavailable, domain.NewError(domain.CodeUnavailable, "too many concurrent requests"), requestIDFrom(r))
		}
	})
}

func isProbe(path string) bool {
	return path == "/health/live" || path == "/health/ready"
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

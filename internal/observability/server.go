package observability

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// Options construct the dedicated metrics/pprof listener.
type Options struct {
	MetricsEnabled bool
	MetricsBind    string
	MetricsPath    string
	ExposeOnAdmin  bool
	TracingEnabled bool
	PprofEnabled   bool
}

// Server is the optional Prometheus scrape listener.
type Server struct {
	opts Options
	Reg  *Registry
	Rec  *Recorder
	Tr   *Tracer
	mux  *http.ServeMux
	hs   *http.Server
	ln   net.Listener
}

// New builds a metrics server. The listener is not started until Listen.
func New(opts Options) *Server {
	if opts.MetricsPath == "" {
		opts.MetricsPath = "/metrics"
	}
	if opts.MetricsBind == "" {
		opts.MetricsBind = "127.0.0.1:9090"
	}
	reg := NewRegistry()
	s := &Server{
		opts: opts,
		Reg:  reg,
		Rec:  NewRecorder(reg),
		Tr:   NewTracer(opts.TracingEnabled),
		mux:  http.NewServeMux(),
	}
	if opts.MetricsEnabled {
		s.mux.Handle(opts.MetricsPath, http.HandlerFunc(s.serveMetrics))
	}
	if opts.PprofEnabled {
		MountPprof(s.mux)
	}
	return s
}

func (s *Server) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_ = s.Reg.WritePrometheus(w)
}

// Handler is the dedicated metrics mux. It is never the admin mux.
func (s *Server) Handler() http.Handler { return s.mux }

// AdminMetricsHandler returns /metrics for optional admin exposure.
// Profiling is never included.
func (s *Server) AdminMetricsHandler() http.Handler {
	if s == nil || !s.opts.ExposeOnAdmin || !s.opts.MetricsEnabled {
		return nil
	}
	return http.HandlerFunc(s.serveMetrics)
}

// NeedsListener reports whether a dedicated socket should be bound.
func (s *Server) NeedsListener() bool {
	if s == nil {
		return false
	}
	return s.opts.MetricsEnabled || s.opts.PprofEnabled
}

// Bind is the configured dedicated bind address. When only pprof is on and
// metrics are off, the loopback pprof default is used.
func (s *Server) Bind() string {
	if s == nil {
		return ""
	}
	if s.opts.MetricsEnabled {
		return s.opts.MetricsBind
	}
	if s.opts.PprofEnabled {
		return DefaultPprofBind
	}
	return ""
}

// Listen binds the dedicated socket. It does not serve.
func (s *Server) Listen() error {
	if s == nil || !s.NeedsListener() {
		return nil
	}
	ln, err := net.Listen("tcp", s.Bind())
	if err != nil {
		return err
	}
	s.ln = ln
	s.hs = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return nil
}

// Addr is the bound dedicated address.
func (s *Server) Addr() net.Addr {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve runs the dedicated listener until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.hs == nil || s.ln == nil {
		<-ctx.Done()
		return nil
	}
	go func() {
		<-ctx.Done()
		_ = s.hs.Close()
	}()
	err := s.hs.Serve(s.ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown stops the dedicated listener.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.hs == nil {
		return nil
	}
	return s.hs.Shutdown(ctx)
}

// PathOK reports whether p is the configured metrics path.
func PathOK(path, configured string) bool {
	if configured == "" {
		configured = "/metrics"
	}
	return path == configured || strings.TrimSuffix(path, "/") == strings.TrimSuffix(configured, "/")
}

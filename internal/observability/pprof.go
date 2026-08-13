package observability

import (
	"net/http"
	"net/http/pprof"
)

// DefaultPprofBind is the loopback-only profile socket used when profiling is
// enabled and the metrics listener is not running.
const DefaultPprofBind = "127.0.0.1:6060"

// MountPprof registers net/http/pprof handlers. Callers must only invoke this
// on the dedicated metrics/pprof mux, never on the admin listener.
func MountPprof(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// PprofEnabled reports whether profiling handlers should be mounted.
func PprofEnabled(enabled bool) bool { return enabled }

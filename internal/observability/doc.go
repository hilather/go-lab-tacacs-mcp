// Package observability implements logs, Prometheus metrics, tracing hooks,
// optional pprof, and resource governors.
//
// Metrics use bounded labels only. Secret-lifecycle series never carry
// client_id, fingerprint, or raw address labels. Tracing and pprof are off
// by default and are never mounted on the admin listener unless an operator
// explicitly enables profiling on the dedicated metrics socket.
package observability

// Package observability implements logs, Prometheus metrics, tracing hooks,
// optional pprof, and resource governors.
//
// Metrics use bounded labels only. Secret-lifecycle series never carry
// client_id, fingerprint, or raw address labels. RADIUS series accept only
// closed protocol/role/reason_code/outcome (plus transport/code/result/type)
// and never client_id, User-Name, or addresses. Tracing and pprof are off
// by default and are never mounted on the admin listener unless an operator
// explicitly enables profiling on the dedicated metrics socket.
package observability

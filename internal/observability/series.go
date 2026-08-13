package observability

// Prometheus series names. Names are the 1.0 contract.
const (
	MetricConnectionsActive     = "taclab_connections_active"
	MetricConnectionsAccepted   = "taclab_connections_accepted_total"
	MetricConnectionsRejected   = "taclab_connections_rejected_total"
	MetricSessionsActive        = "taclab_sessions_active"
	MetricAuthenTotal           = "taclab_authen_total"
	MetricAuthorTotal           = "taclab_author_total"
	MetricAcctTotal             = "taclab_acct_total"
	MetricProtocolErrors        = "taclab_protocol_errors_total"
	MetricAPIRequests           = "taclab_api_requests_total"
	MetricAPIDuration           = "taclab_api_request_duration_seconds"
	MetricMCPTools              = "taclab_mcp_tools_total"
	MetricMCPDuration           = "taclab_mcp_tool_duration_seconds"
	MetricStateRevision         = "taclab_state_revision"
	MetricReloadTotal           = "taclab_reload_total"
	MetricSecretLifecycle       = "taclab_secret_lifecycle"
	MetricSecretWarnings        = "taclab_secret_warnings_total"
	MetricEventSubscribers      = "taclab_event_subscribers"
	MetricEventOverwritten      = "taclab_event_overwritten_total"
	MetricEventSubscriberResets = "taclab_event_subscriber_reset_total"
	MetricGoGoroutines          = "go_goroutines"
	MetricGoThreads             = "go_threads"
	MetricGoMemAllocBytes       = "go_memstats_alloc_bytes"
	MetricGoMemSysBytes         = "go_memstats_sys_bytes"
	MetricGoMemHeapAllocBytes   = "go_memstats_heap_alloc_bytes"
	MetricGoMemHeapInuseBytes   = "go_memstats_heap_inuse_bytes"
	MetricGoMemHeapObjects      = "go_memstats_heap_objects"
	MetricGoGCPauseSeconds      = "go_gc_duration_seconds"
	MetricGoNumGC               = "go_memstats_num_gc_total"
)

// Label names that may appear on any series.
const (
	LabelListener    = "listener"
	LabelTransport   = "transport"
	LabelResultClass = "result_class"
	LabelAuthenType  = "authen_type"
	LabelClientID    = "client_id"
	LabelOperationID = "operation_id"
	LabelErrorCode   = "error_code"
	LabelStatus      = "status"
)

// Forbidden label keys: unbounded or secret-adjacent cardinality.
var forbiddenLabelKeys = map[string]struct{}{
	"username":      {},
	"user_id":       {},
	"user":          {},
	"token_id":      {},
	"token":         {},
	"command":       {},
	"cmd":           {},
	"fingerprint":   {},
	"address":       {},
	"remote":        {},
	"peer":          {},
	"ip":            {},
	"client_ip":     {},
	"raw_address":   {},
	"password":      {},
	"secret":        {},
	"shared_secret": {},
}

// lifecycleSeries reject every extra label except status.
var lifecycleSeries = map[string]struct{}{
	MetricSecretLifecycle: {},
	MetricSecretWarnings:  {},
}

// allowedLabels is the per-series allowlist. Unknown series reject all labels.
var allowedLabels = map[string]map[string]struct{}{
	MetricConnectionsActive:     keys(LabelListener, LabelTransport, LabelClientID),
	MetricConnectionsAccepted:   keys(LabelListener, LabelTransport, LabelClientID),
	MetricConnectionsRejected:   keys(LabelListener, LabelTransport, LabelErrorCode),
	MetricSessionsActive:        keys(LabelListener, LabelTransport),
	MetricAuthenTotal:           keys(LabelTransport, LabelAuthenType, LabelResultClass),
	MetricAuthorTotal:           keys(LabelTransport, LabelResultClass),
	MetricAcctTotal:             keys(LabelTransport, LabelResultClass),
	MetricProtocolErrors:        keys(LabelListener, LabelTransport, LabelErrorCode),
	MetricAPIRequests:           keys(LabelOperationID, LabelResultClass, LabelErrorCode),
	MetricAPIDuration:           keys(LabelOperationID),
	MetricMCPTools:              keys(LabelOperationID, LabelResultClass, LabelErrorCode),
	MetricMCPDuration:           keys(LabelOperationID),
	MetricStateRevision:         keys(),
	MetricReloadTotal:           keys(LabelResultClass),
	MetricSecretLifecycle:       keys(LabelStatus),
	MetricSecretWarnings:        keys(LabelStatus),
	MetricEventSubscribers:      keys(),
	MetricEventOverwritten:      keys(),
	MetricEventSubscriberResets: keys(),
	MetricGoGoroutines:          keys(),
	MetricGoThreads:             keys(),
	MetricGoMemAllocBytes:       keys(),
	MetricGoMemSysBytes:         keys(),
	MetricGoMemHeapAllocBytes:   keys(),
	MetricGoMemHeapInuseBytes:   keys(),
	MetricGoMemHeapObjects:      keys(),
	MetricGoGCPauseSeconds:      keys(),
	MetricGoNumGC:               keys(),
}

func keys(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// Listener and transport enums used as metric labels.
const (
	ListenerLegacy  = "legacy_tacacs"
	ListenerSecure  = "secure_tacacs"
	ListenerHTTP    = "http"
	ListenerMetrics = "metrics"

	TransportLegacy = "legacy"
	TransportTLS    = "tls"
	TransportHTTP   = "http"

	ResultSuccess = "success"
	ResultError   = "error"
	ResultFail    = "fail"
	ResultDeny    = "deny"
	ResultReject  = "reject"
	ResultRestart = "restart"

	StatusCurrent = "current"
	StatusDueSoon = "due_soon"
	StatusOverdue = "overdue"
	StatusUnknown = "unknown"
	// StatusReuse is warnings-only; it is not a lifecycle gauge label.
	StatusReuse = "reuse"
)

// SecretLifecycleStatuses is the closed set of lifecycle gauge labels.
var SecretLifecycleStatuses = []string{StatusCurrent, StatusDueSoon, StatusOverdue, StatusUnknown}

func knownListener(v string) bool {
	switch v {
	case ListenerLegacy, ListenerSecure, ListenerHTTP, ListenerMetrics:
		return true
	default:
		return false
	}
}

func knownTransport(v string) bool {
	switch v {
	case TransportLegacy, TransportTLS, TransportHTTP:
		return true
	default:
		return false
	}
}

func knownLifecycleStatus(v string) bool {
	switch v {
	case StatusCurrent, StatusDueSoon, StatusOverdue, StatusUnknown:
		return true
	default:
		return false
	}
}

func knownWarningStatus(v string) bool {
	return knownLifecycleStatus(v) || v == StatusReuse
}

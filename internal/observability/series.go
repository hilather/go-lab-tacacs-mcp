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

	// RADIUS / protocol-neutral series. TACACS authen/author/acct series stay
	// connection-oriented so historical scrapes do not mix UDP outcomes.
	MetricProtocolRequests              = "taclab_protocol_requests_total"
	MetricProtocolDiscards              = "taclab_protocol_discards_total"
	MetricProtocolDuration              = "taclab_protocol_request_duration_seconds"
	MetricRADIUSQueueDepth              = "taclab_radius_queue_depth"
	MetricRADIUSInflight                = "taclab_radius_inflight"
	MetricRADIUSRetransmission          = "taclab_radius_retransmission_total"
	MetricRADIUSCacheEntries            = "taclab_radius_cache_entries"
	MetricRADIUSCacheSaturations        = "taclab_radius_cache_saturations_total"
	MetricRADIUSJournalSaturations      = "taclab_radius_journal_saturations_total"
	MetricRADIUSAuthenticatorFail       = "taclab_radius_authenticator_failures_total"
	MetricRADIUSChallenges              = "taclab_radius_challenges_total"
	MetricRADIUSChallengeEntries        = "taclab_radius_challenge_entries"
	MetricRADIUSChallengeSaturations    = "taclab_radius_challenge_saturations_total"
	MetricRADIUSSessionIndexEntries     = "taclab_radius_session_index_entries"
	MetricRADIUSSessionIndexSaturations = "taclab_radius_session_index_saturations_total"
	MetricRADIUSDynAuthTotal            = "taclab_radius_dynauth_total"
	MetricRADIUSEAP                     = "taclab_radius_eap_total"
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
	LabelProtocol    = "protocol"
	LabelRole        = "role"
	LabelReasonCode  = "reason_code"
	LabelOutcome     = "outcome"
	LabelPacketCode  = "code"
	LabelResult      = "result"
	LabelType        = "type"
	LabelDirection   = "direction"
	LabelEAPType     = "eap_type"
)

// Forbidden label keys: unbounded or secret-adjacent cardinality.
// RADIUS series also omit client_id via the per-series allowlist.
var forbiddenLabelKeys = map[string]struct{}{
	"username":              {},
	"user_id":               {},
	"user":                  {},
	"user_name":             {},
	"token_id":              {},
	"token":                 {},
	"command":               {},
	"cmd":                   {},
	"fingerprint":           {},
	"address":               {},
	"remote":                {},
	"peer":                  {},
	"ip":                    {},
	"client_ip":             {},
	"source_ip":             {},
	"nas_ip":                {},
	"framed_ip":             {},
	"raw_address":           {},
	"password":              {},
	"secret":                {},
	"shared_secret":         {},
	"nas_identifier":        {},
	"calling_station_id":    {},
	"called_station_id":     {},
	"acct_session_id":       {},
	"state":                 {},
	"authenticator":         {},
	"user_password":         {},
	"radius_secret":         {},
	"message_authenticator": {},
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
	// RADIUS series never accept client_id, username, or addresses.
	MetricProtocolRequests:              keys(LabelProtocol, LabelTransport, LabelRole, LabelPacketCode, LabelOutcome),
	MetricProtocolDiscards:              keys(LabelProtocol, LabelTransport, LabelRole, LabelReasonCode),
	MetricProtocolDuration:              keys(LabelProtocol, LabelTransport, LabelRole, LabelPacketCode, LabelOutcome),
	MetricRADIUSQueueDepth:              keys(LabelRole),
	MetricRADIUSInflight:                keys(LabelRole),
	MetricRADIUSRetransmission:          keys(LabelRole, LabelResult),
	MetricRADIUSCacheEntries:            keys(LabelRole),
	MetricRADIUSCacheSaturations:        keys(LabelRole),
	MetricRADIUSJournalSaturations:      keys(LabelRole),
	MetricRADIUSAuthenticatorFail:       keys(LabelRole, LabelType),
	MetricRADIUSChallenges:              keys(LabelResult),
	MetricRADIUSChallengeEntries:        keys(),
	MetricRADIUSChallengeSaturations:    keys(),
	MetricRADIUSSessionIndexEntries:     keys(),
	MetricRADIUSSessionIndexSaturations: keys(),
	MetricRADIUSDynAuthTotal:            keys(LabelDirection, LabelPacketCode, LabelOutcome),
	MetricRADIUSEAP:                     keys(LabelEAPType, LabelOutcome),
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
	ListenerLegacy           = "legacy_tacacs"
	ListenerSecure           = "secure_tacacs"
	ListenerHTTP             = "http"
	ListenerMetrics          = "metrics"
	ListenerRADIUSAccess     = "radius_access"
	ListenerRADIUSAccounting = "radius_accounting"
	ListenerRADIUSRadSec     = "radius_radsec"
	ListenerRADIUSDynAuth    = "radius_dynauth"

	TransportLegacy = "legacy"
	TransportTLS    = "tls"
	TransportHTTP   = "http"
	TransportUDP    = "udp"

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

	ProtocolTACACS = "tacacs"
	ProtocolRADIUS = "radius"
	ProtocolHTTP   = "http"

	RoleAccess               = "access"
	RoleAccounting           = "accounting"
	RoleAAA                  = "aaa"
	RoleAuthentication       = "authentication"
	RoleAuthorization        = "authorization"
	RoleAdmin                = "admin"
	RoleDynamicAuthorization = "dynamic_authorization"

	OutcomeAccessAccept    = "access_accept"
	OutcomeAccessReject    = "access_reject"
	OutcomeAccessChallenge = "access_challenge"
	OutcomeOK              = "ok"
	OutcomeDiscard         = "discard"
	OutcomeDrop            = "drop"
	OutcomeError           = "error"
	OutcomeACK             = "ack"
	OutcomeNAK             = "nak"
	OutcomeTimeout         = "timeout"

	DirectionOut = "out"
	DirectionIn  = "in"

	CodeAccessRequest      = "access_request"
	CodeAccessAccept       = "access_accept"
	CodeAccessReject       = "access_reject"
	CodeAccountingRequest  = "accounting_request"
	CodeAccountingResponse = "accounting_response"
	CodeAccessChallenge    = "access_challenge"
	CodeDisconnectRequest  = "disconnect_request"
	CodeDisconnectACK      = "disconnect_ack"
	CodeDisconnectNAK      = "disconnect_nak"
	CodeCoARequest         = "coa_request"
	CodeCoAACK             = "coa_ack"
	CodeCoANAK             = "coa_nak"

	RetransmitHitCompleted = "hit_completed"
	RetransmitHitPending   = "hit_pending"
	RetransmitMiss         = "miss"
	RetransmitPurge        = "purge"

	ChallengeResultIssue        = "issue"
	ChallengeResultContinue     = "continue"
	ChallengeResultReplayReject = "replay_reject"
	ChallengeResultExpired      = "expired"
	ChallengeResultBinding      = "binding"
	ChallengeResultCapacity     = "capacity"

	AuthTypeMessageAuthenticator = "message_authenticator"
	AuthTypeAccountingRequest    = "accounting_request"
	AuthTypeResponse             = "response"

	EAPTypeIdentity = "identity"
	EAPTypeMD5      = "md5"
	EAPTypeNAK      = "nak"
	EAPTypeOther    = "other"
)

// SecretLifecycleStatuses is the closed set of lifecycle gauge labels.
var SecretLifecycleStatuses = []string{StatusCurrent, StatusDueSoon, StatusOverdue, StatusUnknown}

func knownListener(v string) bool {
	switch v {
	case ListenerLegacy, ListenerSecure, ListenerHTTP, ListenerMetrics,
		ListenerRADIUSAccess, ListenerRADIUSAccounting, ListenerRADIUSRadSec, ListenerRADIUSDynAuth:
		return true
	default:
		return false
	}
}

func knownTransport(v string) bool {
	switch v {
	case TransportLegacy, TransportTLS, TransportHTTP, TransportUDP:
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

func knownProtocol(v string) bool {
	switch v {
	case ProtocolTACACS, ProtocolRADIUS, ProtocolHTTP:
		return true
	default:
		return false
	}
}

func knownRole(v string) bool {
	switch v {
	case RoleAccess, RoleAccounting, RoleAAA, RoleAuthentication,
		RoleAuthorization, RoleAdmin, RoleDynamicAuthorization:
		return true
	default:
		return false
	}
}

func knownOutcome(v string) bool {
	switch v {
	case OutcomeAccessAccept, OutcomeAccessReject, OutcomeAccessChallenge, OutcomeOK,
		OutcomeDiscard, OutcomeDrop, OutcomeError,
		OutcomeACK, OutcomeNAK, OutcomeTimeout:
		return true
	default:
		return false
	}
}

func knownPacketCode(v string) bool {
	switch v {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge,
		CodeCoARequest, CodeCoAACK, CodeCoANAK,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK:
		return true
	default:
		return false
	}
}

func knownDirection(v string) bool {
	switch v {
	case DirectionIn, DirectionOut:
		return true
	default:
		return false
	}
}

func knownRetransmitResult(v string) bool {
	switch v {
	case RetransmitHitCompleted, RetransmitHitPending, RetransmitMiss, RetransmitPurge:
		return true
	default:
		return false
	}
}

func knownChallengeResult(v string) bool {
	switch v {
	case ChallengeResultIssue, ChallengeResultContinue, ChallengeResultReplayReject,
		ChallengeResultExpired, ChallengeResultBinding, ChallengeResultCapacity:
		return true
	default:
		return false
	}
}

func knownAuthenticatorType(v string) bool {
	switch v {
	case AuthTypeMessageAuthenticator, AuthTypeAccountingRequest, AuthTypeResponse:
		return true
	default:
		return false
	}
}

func knownEAPType(v string) bool {
	switch v {
	case EAPTypeIdentity, EAPTypeMD5, EAPTypeNAK, EAPTypeOther:
		return true
	default:
		return false
	}
}

// Closed §5.7 reason_code set plus documented lab extras (secret missing,
// journal saturation sampled as a discard of a ring append, not of the ack).
func knownReasonCode(v string) bool {
	switch v {
	case "ok",
		"discard_unknown_client",
		"discard_ambiguous_client",
		"discard_malformed_header",
		"discard_invalid_length",
		"discard_invalid_code",
		"discard_invalid_accounting_request_authenticator",
		"discard_invalid_message_authenticator",
		"discard_eap_without_ma",
		"discard_missing_message_authenticator",
		"discard_proxy_state_without_ma",
		"discard_unknown_acct_status",
		"drop_overload",
		"reject_missing_username",
		"reject_conflicting_auth",
		"reject_chap_password_length",
		"reject_unsupported_method",
		"reject_bad_credentials",
		"reject_password_change_required",
		"reject_policy",
		"reject_invalid_state",
		"reject_challenge_expired",
		"reject_challenge_binding",
		"reject_challenge_capacity",
		"challenge",
		"reject_unsupported_eap_method",
		"reject_eap_too_long",
		"internal_error",
		"ambiguous_identity",
		"secret_unavailable",
		"journal_saturated",
		"session_context_not_found",
		"unsupported_attribute",
		"multiple_session_selection":
		return true
	default:
		return false
	}
}

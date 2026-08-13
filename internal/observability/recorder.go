package observability

import (
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Recorder is the adapter-facing metrics API. All methods are nil-safe.
type Recorder struct {
	Reg *Registry
}

// NewRecorder wraps a registry. A nil registry yields a no-op recorder.
func NewRecorder(reg *Registry) *Recorder {
	if reg == nil {
		return nil
	}
	return &Recorder{Reg: reg}
}

func (r *Recorder) registry() *Registry {
	if r == nil {
		return nil
	}
	return r.Reg
}

// ConnectionAccepted increments the accepted-connection counter.
func (r *Recorder) ConnectionAccepted(listener, transport string) {
	r.registry().Inc(MetricConnectionsAccepted, Labels{LabelListener: listener, LabelTransport: transport}, 1)
	r.registry().AddGauge(MetricConnectionsActive, Labels{LabelListener: listener, LabelTransport: transport}, 1)
}

// ConnectionClosed decrements the active-connection gauge.
func (r *Recorder) ConnectionClosed(listener, transport string) {
	r.registry().AddGauge(MetricConnectionsActive, Labels{LabelListener: listener, LabelTransport: transport}, -1)
}

// ConnectionRejected increments the rejected-connection counter.
func (r *Recorder) ConnectionRejected(listener, transport, code string) {
	if code == "" {
		code = "protocol"
	}
	r.registry().Inc(MetricConnectionsRejected, Labels{LabelListener: listener, LabelTransport: transport, LabelErrorCode: code}, 1)
}

// SessionOpen increments the active-session gauge.
func (r *Recorder) SessionOpen(listener, transport string) {
	r.registry().AddGauge(MetricSessionsActive, Labels{LabelListener: listener, LabelTransport: transport}, 1)
}

// SessionClose decrements the active-session gauge.
func (r *Recorder) SessionClose(listener, transport string) {
	r.registry().AddGauge(MetricSessionsActive, Labels{LabelListener: listener, LabelTransport: transport}, -1)
}

// Authen records one authentication outcome.
func (r *Recorder) Authen(transport, authenType, result string) {
	r.registry().Inc(MetricAuthenTotal, Labels{
		LabelTransport:   boundTransport(transport),
		LabelAuthenType:  boundAuthenType(authenType),
		LabelResultClass: boundAuthenResult(result),
	}, 1)
}

// Author records one authorization outcome.
func (r *Recorder) Author(transport, result string) {
	r.registry().Inc(MetricAuthorTotal, Labels{
		LabelTransport:   boundTransport(transport),
		LabelResultClass: boundAuthorResult(result),
	}, 1)
}

// Acct records one accounting outcome.
func (r *Recorder) Acct(transport, result string) {
	r.registry().Inc(MetricAcctTotal, Labels{
		LabelTransport:   boundTransport(transport),
		LabelResultClass: boundAcctResult(result),
	}, 1)
}

// ProtocolError records a connection-level protocol failure.
func (r *Recorder) ProtocolError(listener, transport, code string) {
	if code == "" {
		code = "protocol"
	}
	r.registry().Inc(MetricProtocolErrors, Labels{LabelListener: listener, LabelTransport: transport, LabelErrorCode: code}, 1)
}

// API records one REST operation.
func (r *Recorder) API(operationID, result, errCode string, seconds float64) {
	if errCode == "" {
		errCode = "none"
	}
	r.registry().Inc(MetricAPIRequests, Labels{LabelOperationID: operationID, LabelResultClass: boundAPIResult(result), LabelErrorCode: errCode}, 1)
	r.registry().Observe(MetricAPIDuration, Labels{LabelOperationID: operationID}, seconds)
}

// MCP records one MCP tool call.
func (r *Recorder) MCP(operationID, result, errCode string, seconds float64) {
	if errCode == "" {
		errCode = "none"
	}
	if operationID == "" {
		operationID = "unknown"
	}
	r.registry().Inc(MetricMCPTools, Labels{LabelOperationID: operationID, LabelResultClass: boundAPIResult(result), LabelErrorCode: errCode}, 1)
	r.registry().Observe(MetricMCPDuration, Labels{LabelOperationID: operationID}, seconds)
}

// SetRevision writes the published snapshot revision.
func (r *Recorder) SetRevision(rev uint64) {
	r.registry().Set(MetricStateRevision, nil, float64(rev))
}

// Reload records a reload attempt.
func (r *Recorder) Reload(ok bool) {
	cls := ResultError
	if ok {
		cls = ResultSuccess
	}
	r.registry().Inc(MetricReloadTotal, Labels{LabelResultClass: cls}, 1)
}

// SetSecretLifecycle replaces lifecycle gauges. Status is the only label.
func (r *Recorder) SetSecretLifecycle(counts map[string]int) {
	reg := r.registry()
	if reg == nil {
		return
	}
	for _, st := range SecretLifecycleStatuses {
		n := 0
		if counts != nil {
			n = counts[st]
		}
		reg.Set(MetricSecretLifecycle, Labels{LabelStatus: st}, float64(n))
	}
}

// SecretWarning increments the warning counter. Status is the only label.
func (r *Recorder) SecretWarning(status string) {
	if !knownLifecycleStatus(status) {
		status = StatusUnknown
	}
	r.registry().Inc(MetricSecretWarnings, Labels{LabelStatus: status}, 1)
}

// SetEventSubscribers writes the live subscriber gauge.
func (r *Recorder) SetEventSubscribers(n int) {
	r.registry().Set(MetricEventSubscribers, nil, float64(n))
}

// EventOverwritten records newly overwritten ring entries.
func (r *Recorder) EventOverwritten(n uint64) {
	if n == 0 {
		return
	}
	r.registry().Inc(MetricEventOverwritten, nil, n)
}

// EventSubscriberReset increments the slow-subscriber counter.
func (r *Recorder) EventSubscriberReset() {
	r.registry().Inc(MetricEventSubscriberResets, nil, 1)
}

func boundTransport(v string) string {
	switch strings.ToLower(v) {
	case TransportLegacy:
		return TransportLegacy
	case TransportTLS, "secure":
		return TransportTLS
	case TransportHTTP:
		return TransportHTTP
	default:
		return TransportLegacy
	}
}

func boundAuthenType(v string) string {
	v = strings.ToLower(v)
	switch {
	case strings.Contains(v, "mschapv2"):
		return "mschapv2"
	case strings.Contains(v, "mschap"):
		return "mschap"
	case strings.Contains(v, "chap"):
		return "chap"
	case strings.Contains(v, "pap"):
		return "pap"
	case strings.Contains(v, "enable"):
		return "enable"
	case strings.Contains(v, "chpass"):
		return "chpass"
	case strings.Contains(v, "ascii"):
		return "ascii"
	default:
		return "unknown"
	}
}

func boundAuthenResult(v string) string {
	switch strings.ToLower(v) {
	case "pass", ResultSuccess:
		return ResultSuccess
	case ResultFail:
		return ResultFail
	case "restart":
		return ResultRestart
	default:
		return ResultError
	}
}

func boundAuthorResult(v string) string {
	switch strings.ToLower(v) {
	case "permit_add", "pass_add":
		return "permit_add"
	case "permit_replace", "pass_repl":
		return "permit_replace"
	case "deny", "fail":
		return ResultDeny
	default:
		return ResultError
	}
}

func boundAcctResult(v string) string {
	switch strings.ToLower(v) {
	case "success", "ok", "pass":
		return ResultSuccess
	case "fail", "error":
		return ResultError
	default:
		return ResultError
	}
}

func boundAPIResult(v string) string {
	switch strings.ToLower(v) {
	case ResultSuccess, "":
		return ResultSuccess
	case "unauthenticated", "permission_denied", "invalid_argument",
		"rate_limited", "unavailable", "conflict", "revision_mismatch",
		"already_exists", "not_found":
		return strings.ToLower(v)
	default:
		return ResultError
	}
}

// ResultFromError maps a domain error to result_class and error_code.
func ResultFromError(err error) (result, code string) {
	if err == nil {
		return ResultSuccess, "none"
	}
	if de, ok := domain.AsError(err); ok {
		c := string(de.Code)
		switch de.Code {
		case domain.CodeUnauthenticated:
			return "unauthenticated", c
		case domain.CodePermissionDenied:
			return "permission_denied", c
		case domain.CodeInvalidArgument:
			return "invalid_argument", c
		case domain.CodeRateLimited:
			return "rate_limited", c
		case domain.CodeUnavailable:
			return "unavailable", c
		case domain.CodeConflict:
			return "conflict", c
		case domain.CodeRevisionMismatch:
			return "revision_mismatch", c
		case domain.CodeAlreadyExists:
			return "already_exists", c
		case domain.CodeNotFound:
			return "not_found", c
		default:
			return ResultError, c
		}
	}
	return ResultError, "internal"
}

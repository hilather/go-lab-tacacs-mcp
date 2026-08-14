package aaa

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

// AccountingKind is a RADIUS Acct-Status-Type the AAA service will record.
// It is not a TACACS accounting flag byte.
type AccountingKind string

const (
	AccountingStart   AccountingKind = "start"
	AccountingStop    AccountingKind = "stop"
	AccountingInterim AccountingKind = "interim_update"
	AccountingOn      AccountingKind = "accounting_on"
	AccountingOff     AccountingKind = "accounting_off"
)

// Valid reports whether k is a RADIUS accounting kind this service records.
func (k AccountingKind) Valid() bool {
	switch k {
	case AccountingStart, AccountingStop, AccountingInterim, AccountingOn, AccountingOff:
		return true
	default:
		return false
	}
}

func (k AccountingKind) String() string { return string(k) }

// SafeAttributeSummary is a RADIUS attribute name (and optional occurrence
// count) already stripped of values. RecordRADIUSAccounting never stores
// attribute values; EventAV.Value is always the redacted sentinel.
type SafeAttributeSummary struct {
	Name  string
	Count int
}

// RADIUSAccountingRecord is one RADIUS accounting request in domain terms.
// SessionID is Acct-Session-Id text. Do not put it in AccountingRecord.Flags
// or Event.SessionID (TACACS uint32).
type RADIUSAccountingRecord struct {
	Context        domain.RequestContext
	Kind           AccountingKind
	UserID         string
	SessionID      string
	StartedAt      *time.Time
	SessionTime    time.Duration
	InputOctets    uint64
	OutputOctets   uint64
	TerminateCause string
	SafeAttributes []SafeAttributeSummary
	IdempotencyKey string
}

// RecordRADIUSAccounting accepts a RADIUS accounting record into the ring.
// SUCCESS (OK + EventID) is returned only after the ring assigns an ID.
// Event.SessionID stays 0; Acct-Session-Id is Event.AcctSessionID.
func (s *Service) RecordRADIUSAccounting(ctx context.Context, rec RADIUSAccountingRecord) (AccountingResult, error) {
	if err := ctx.Err(); err != nil {
		return AccountingResult{}, err
	}
	if s == nil || s.events == nil {
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if !rec.Kind.Valid() {
		return AccountingResult{}, domain.NewError(domain.CodeInvalidArgument, "accounting kind must be start, stop, interim_update, accounting_on, or accounting_off").
			WithDetail("kind", rec.Kind.String())
	}
	if rec.Context.Protocol != "" && rec.Context.Protocol != domain.ProtocolRADIUS {
		return AccountingResult{}, domain.NewError(domain.CodeInvalidArgument, "RADIUS accounting protocol must be radius").
			WithDetail("protocol", rec.Context.Protocol.String())
	}
	if rec.TerminateCause != "" {
		canon, ok := canonicalTerminateCause(rec.TerminateCause)
		if !ok {
			return AccountingResult{}, domain.NewError(domain.CodeInvalidArgument, "unknown accounting terminate cause").
				WithDetail("terminate_cause", rec.TerminateCause)
		}
		rec.TerminateCause = canon
	}
	if err := checkSafeAttributeBudget(s, rec.SafeAttributes); err != nil {
		return AccountingResult{}, err
	}

	protocol := rec.Context.Protocol.String()
	if protocol == "" {
		protocol = domain.ProtocolRADIUS.String()
	}
	role := rec.Context.ListenerRole.String()
	if role == "" {
		role = domain.RoleAccounting.String()
	}

	ev := events.Event{
		Category:       events.CategoryAcct,
		Type:           rec.Kind.String(),
		Result:         "success",
		Protocol:       protocol,
		Carrier:        rec.Context.Carrier.String(),
		ListenerRole:   role,
		ListenerID:     rec.Context.ListenerID,
		EndpointID:     rec.Context.EndpointID,
		ClientID:       rec.Context.ClientID,
		Revision:       rec.Context.SnapshotRevision,
		UserID:         rec.UserID,
		AcctSessionID:  rec.SessionID,
		Outcome:        "success",
		SuppressExport: !includeAccounting(s.snap()),
	}
	if rec.Context.Peer.IsValid() {
		ev.Remote = rec.Context.Peer.String()
	}
	if rec.StartedAt != nil {
		t := rec.StartedAt.UTC()
		ev.StartTime = &t
	}
	ev.Arguments = radiusAccountingAVs(rec)

	// SUCCESS only after the ring assigns an ID. AcctSessionID stays for events:sensitive.
	accepted := s.events.Accept(ev)
	if accepted.ID == 0 {
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "accounting ring rejected the record")
	}
	return AccountingResult{OK: true, EventID: accepted.ID}, nil
}

func checkSafeAttributeBudget(s *Service, attrs []SafeAttributeSummary) error {
	if len(attrs) == 0 {
		return nil
	}
	maxArgs := 256
	snap := s.snap()
	if snap != nil && snap.Settings() != nil && snap.Settings().Limits.MaxAuthorizationArguments > 0 {
		maxArgs = snap.Settings().Limits.MaxAuthorizationArguments
	}
	return observability.CheckCount("arguments", len(attrs), maxArgs)
}

func radiusAccountingAVs(rec RADIUSAccountingRecord) []events.EventAV {
	seenSession := false
	out := make([]events.EventAV, 0, len(rec.SafeAttributes)+4)
	for _, a := range rec.SafeAttributes {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "Acct-Session-Id") || strings.HasPrefix(strings.ToLower(name), "acct-session-id#") {
			seenSession = true
		}
		if a.Count > 1 {
			name = fmt.Sprintf("%s#%d", name, a.Count)
		}
		// Values are never stored. Restricted and secret names stay names only.
		out = append(out, events.RedactedAV(name))
	}
	if rec.SessionID != "" && !seenSession {
		out = append(out, events.RedactedAV("Acct-Session-Id"))
	}
	if rec.InputOctets != 0 {
		out = append(out, events.EventAV{Name: "Acct-Input-Octets", Value: strconv.FormatUint(rec.InputOctets, 10)})
	}
	if rec.OutputOctets != 0 {
		out = append(out, events.EventAV{Name: "Acct-Output-Octets", Value: strconv.FormatUint(rec.OutputOctets, 10)})
	}
	if rec.SessionTime > 0 {
		out = append(out, events.EventAV{Name: "Acct-Session-Time", Value: strconv.FormatInt(int64(rec.SessionTime/time.Second), 10)})
	}
	if rec.TerminateCause != "" {
		out = append(out, events.EventAV{Name: "Acct-Terminate-Cause", Value: rec.TerminateCause})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RFC 2866 §5.10 Acct-Terminate-Cause names (IANA dictionary).
var terminateCauses = map[string]string{
	"user-request":        "User-Request",
	"lost-carrier":        "Lost-Carrier",
	"lost-service":        "Lost-Service",
	"idle-timeout":        "Idle-Timeout",
	"session-timeout":     "Session-Timeout",
	"admin-reset":         "Admin-Reset",
	"admin-reboot":        "Admin-Reboot",
	"port-error":          "Port-Error",
	"nas-error":           "NAS-Error",
	"nas-request":         "NAS-Request",
	"nas-reboot":          "NAS-Reboot",
	"port-unneeded":       "Port-Unneeded",
	"port-preempted":      "Port-Preempted",
	"port-suspended":      "Port-Suspended",
	"service-unavailable": "Service-Unavailable",
	"callback":            "Callback",
	"user-error":          "User-Error",
	"host-request":        "Host-Request",
}

func canonicalTerminateCause(s string) (string, bool) {
	key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
	canon, ok := terminateCauses[key]
	return canon, ok
}

package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

// RecordAccounting accepts a valid record into the ring. Invalid flags ERROR.
// SUCCESS is returned only after the ring assigns an event ID.
func (s *Service) RecordAccounting(ctx context.Context, rec AccountingRecord) (AccountingResult, error) {
	if err := ctx.Err(); err != nil {
		return AccountingResult{}, err
	}
	if s == nil || s.events == nil {
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if !ValidAcctFlags(rec.Flags) {
		s.metrics.Acct(string(rec.Transport), "error")
		return AccountingResult{}, domain.NewError(domain.CodeInvalidArgument, "invalid accounting flags").
			WithDetail("flags", rec.Flags)
	}
	if err := s.clientAccepts(rec); err != nil {
		return AccountingResult{}, err
	}

	args := rec.Arguments
	if rec.Flags == AcctFlagWatchdog {
		args = nil
	}
	if err := checkArgBudget(s, args); err != nil {
		return AccountingResult{}, err
	}
	parsed, err := parseAccountingArgs(args)
	if err != nil {
		return AccountingResult{}, err
	}

	kind := acctType(rec.Flags)
	ev := events.Event{
		Category:       events.CategoryAcct,
		Type:           kind,
		Result:         "success",
		Transport:      string(rec.Transport),
		ClientID:       rec.ClientID,
		SessionID:      rec.SessionID,
		Revision:       rec.Revision,
		UserID:         rec.UserID,
		TaskID:         parsed.taskID,
		StartTime:      parsed.startTime,
		StopTime:       parsed.stopTime,
		AuthenMethod:   rec.AuthenMethod.String(),
		AuthenType:     rec.AuthenType.String(),
		Service:        rec.Service.String(),
		Privilege:      uint8(rec.Privilege),
		Port:           rec.Port,
		Remote:         rec.Remote,
		SuppressExport: !includeAccounting(s.snap()),
	}
	if cmd := commandText(args); cmd != "" {
		ev.Command = cmd
	}
	if len(parsed.args) > 0 {
		ev.Arguments = make([]events.EventAV, len(parsed.args))
		for i, a := range parsed.args {
			sep := ""
			if a.pair.Separator != 0 {
				sep = string(a.pair.Separator)
			}
			ev.Arguments[i] = events.EventAV{Name: a.pair.Name, Separator: sep, Value: a.pair.Value}
		}
	}

	// SUCCESS only after the ring assigns an ID. User/command stay for events:sensitive.
	accepted := s.events.Accept(ev)
	if accepted.ID == 0 {
		s.metrics.Acct(string(rec.Transport), "error")
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "accounting ring rejected the record")
	}
	s.metrics.Acct(string(rec.Transport), "success")
	return AccountingResult{OK: true, EventID: accepted.ID}, nil
}

func (s *Service) clientAccepts(rec AccountingRecord) error {
	snap := s.snap()
	if snap == nil || rec.ClientID == "" {
		return nil
	}
	c, ok := snap.Client(rec.ClientID)
	if !ok {
		return nil
	}
	acct := c.Client.Accounting
	if !acct.Enabled {
		return domain.NewError(domain.CodeInvalidArgument, "accounting disabled for client").
			WithDetail("client_id", rec.ClientID)
	}
	switch rec.Flags {
	case AcctFlagStart:
		if !acct.AcceptStart {
			return domain.NewError(domain.CodeInvalidArgument, "client does not accept accounting START").
				WithDetail("client_id", rec.ClientID)
		}
	case AcctFlagStop:
		if !acct.AcceptStop {
			return domain.NewError(domain.CodeInvalidArgument, "client does not accept accounting STOP").
				WithDetail("client_id", rec.ClientID)
		}
	case AcctFlagWatchdog, AcctFlagWatchdogUpdate:
		if !acct.AcceptWatchdog {
			return domain.NewError(domain.CodeInvalidArgument, "client does not accept accounting WATCHDOG").
				WithDetail("client_id", rec.ClientID)
		}
	}
	return nil
}

func checkArgBudget(s *Service, args domain.AVPairs) error {
	if len(args) == 0 {
		return nil
	}
	maxArgs := 256
	snap := s.snap()
	if snap != nil && snap.Settings() != nil && snap.Settings().Limits.MaxAuthorizationArguments > 0 {
		maxArgs = snap.Settings().Limits.MaxAuthorizationArguments
	}
	if len(args) > maxArgs {
		return domain.NewError(domain.CodeInvalidArgument, "too many accounting arguments").
			WithDetail("count", len(args)).
			WithDetail("max", maxArgs)
	}
	return nil
}

func acctType(flags byte) string {
	switch flags {
	case AcctFlagStart:
		return "start"
	case AcctFlagStop:
		return "stop"
	case AcctFlagWatchdog:
		return "watchdog"
	case AcctFlagWatchdogUpdate:
		return "watchdog_update"
	default:
		return "unknown"
	}
}

func commandText(args domain.AVPairs) string {
	var cmd string
	var extras []string
	for _, p := range args {
		switch p.Name {
		case "cmd":
			if cmd == "" {
				cmd = p.Value
			}
		case "cmd-arg":
			extras = append(extras, p.Value)
		}
	}
	if cmd == "" {
		return ""
	}
	if len(extras) == 0 {
		return cmd
	}
	out := cmd
	for _, a := range extras {
		out += " " + a
	}
	return out
}

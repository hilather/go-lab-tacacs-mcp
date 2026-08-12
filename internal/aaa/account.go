package aaa

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
)

// RecordAccounting accepts a valid record into the ring. Invalid flags ERROR.
func (s *Service) RecordAccounting(ctx context.Context, rec AccountingRecord) (AccountingResult, error) {
	if err := ctx.Err(); err != nil {
		return AccountingResult{}, err
	}
	if s == nil || s.events == nil {
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "aaa service is not initialized")
	}
	if !ValidAcctFlags(rec.Flags) {
		return AccountingResult{}, domain.NewError(domain.CodeInvalidArgument, "invalid accounting flags")
	}
	kind := acctType(rec.Flags)
	ev := s.record(events.Event{
		Category:  "acct",
		Type:      kind,
		Result:    "success",
		Transport: string(rec.Transport),
		ClientID:  rec.ClientID,
		SessionID: rec.SessionID,
		Revision:  rec.Revision,
		UserID:    rec.UserID,
	}, redactUserInput(s.snap()))
	if ev.ID == 0 {
		return AccountingResult{}, domain.NewError(domain.CodeInternal, "accounting ring rejected the record")
	}
	return AccountingResult{OK: true, EventID: ev.ID}, nil
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

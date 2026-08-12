package aaa

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestRecordAccountingStart(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStart,
		UserID:    "lab-admin",
		ClientID:  "lab-switches",
		SessionID: 9,
		Revision:  1,
		Transport: domain.TransportLegacy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.EventID == 0 {
		t.Fatalf("result=%+v", res)
	}
	got, ok := ring.Latest()
	if !ok || got.ID != res.EventID || got.Type != "start" || got.Category != "acct" {
		t.Fatalf("ring=%+v", got)
	}
}

func TestRecordAccountingRejectsInvalidFlags(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{Flags: 0})
	if err == nil {
		t.Fatal("expected error")
	}
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}

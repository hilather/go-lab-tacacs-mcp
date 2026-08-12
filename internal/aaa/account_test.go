package aaa

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
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
	if !ok || got.ID != res.EventID || got.Type != "start" || got.Category != events.CategoryAcct {
		t.Fatalf("ring=%+v", got)
	}
}

func TestAccountingFlagTable(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	valid := []struct {
		flags byte
		kind  string
	}{
		{AcctFlagStart, "start"},
		{AcctFlagStop, "stop"},
		{AcctFlagWatchdog, "watchdog"},
		{AcctFlagWatchdogUpdate, "watchdog_update"},
	}
	for _, tc := range valid {
		if !ValidAcctFlags(tc.flags) {
			t.Fatalf("valid %#x rejected", tc.flags)
		}
		res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
			Flags:    tc.flags,
			UserID:   "lab-admin",
			ClientID: "lab-switches",
		})
		if err != nil || !res.OK {
			t.Fatalf("flags=%#x: %+v %v", tc.flags, res, err)
		}
		got, _ := ring.Latest()
		if got.Type != tc.kind || got.ID != res.EventID {
			t.Fatalf("flags=%#x ring=%+v", tc.flags, got)
		}
	}

	invalid := []byte{
		0,
		AcctFlagStart | AcctFlagStop,
		AcctFlagWatchdog | AcctFlagStop,
		AcctFlagStart | AcctFlagStop | AcctFlagWatchdog,
		0x01, 0x10, 0xff,
	}
	for _, f := range invalid {
		if ValidAcctFlags(f) {
			t.Fatalf("invalid %#x accepted by ValidAcctFlags", f)
		}
		_, err := svc.RecordAccounting(context.Background(), AccountingRecord{Flags: f, ClientID: "lab-switches"})
		if err == nil {
			t.Fatalf("flags %#x should ERROR", f)
		}
		if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInvalidArgument {
			t.Fatalf("flags %#x err=%v", f, err)
		}
	}
}

func TestAccountingFullByteTable(t *testing.T) {
	t.Parallel()
	allowed := map[byte]bool{
		AcctFlagStart: true, AcctFlagStop: true,
		AcctFlagWatchdog: true, AcctFlagWatchdogUpdate: true,
	}
	svc, _, _ := testService(t)
	for f := 0; f < 256; f++ {
		b := byte(f)
		_, err := svc.RecordAccounting(context.Background(), AccountingRecord{Flags: b, ClientID: "lab-switches"})
		if allowed[b] {
			if err != nil {
				t.Fatalf("%#x: %v", b, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%#x accepted", b)
		}
	}
}

func TestWatchdogIgnoresArguments(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:    AcctFlagWatchdog,
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			{Name: "task_id", Separator: '=', Value: "should-ignore"},
			{Name: "bytes", Separator: '=', Value: "not-a-number"},
			{Name: "cmd", Separator: '=', Value: "configure"},
		},
	})
	if err != nil || !res.OK {
		t.Fatalf("watchdog: %+v %v", res, err)
	}
	got, _ := ring.Latest()
	if got.Type != "watchdog" || got.TaskID != "" || len(got.Arguments) != 0 || got.Command != "" {
		t.Fatalf("watchdog stored args: %+v", got)
	}
}

func TestWatchdogUpdateKeepsArguments(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:    AcctFlagWatchdogUpdate,
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			{Name: "task_id", Separator: '=', Value: "t1"},
			{Name: "bytes", Separator: '=', Value: "10"},
		},
	})
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := ring.Latest()
	if got.Type != "watchdog_update" || got.TaskID != "t1" || len(got.Arguments) != 2 {
		t.Fatalf("update=%+v", got)
	}
}

func TestTaskIDIsOpaque(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ids := []string{"plain", "!!! not-a-uuid @@@", "task/with spaces", "0"}
	for _, id := range ids {
		res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
			Flags:     AcctFlagStart,
			ClientID:  "lab-switches",
			Arguments: domain.AVPairs{{Name: "task_id", Separator: '=', Value: id}},
		})
		if err != nil || !res.OK {
			t.Fatalf("task_id %q: %v", id, err)
		}
		got, _ := ring.Latest()
		if got.TaskID != id {
			t.Fatalf("stored %q want %q", got.TaskID, id)
		}
	}
}

func TestAccountingPreservesAVOrder(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	args := domain.AVPairs{
		{Name: "task_id", Separator: '=', Value: "sess-9"},
		{Name: "start_time", Separator: '=', Value: "1755000000"},
		{Name: "bytes_in", Separator: '=', Value: "12"},
		{Name: "service", Separator: '=', Value: "shell"},
		{Name: "cmd", Separator: '=', Value: "show"},
		{Name: "cmd-arg", Separator: '=', Value: "running-config"},
		{Name: "cisco-av-pair", Separator: '*', Value: "shell:roles=admin"},
	}
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStop,
		UserID:    "lab-admin",
		ClientID:  "lab-switches",
		Arguments: args,
	})
	if err != nil || !res.OK {
		t.Fatal(err)
	}
	got, _ := ring.Latest()
	if len(got.Arguments) != len(args) {
		t.Fatalf("args=%d", len(got.Arguments))
	}
	for i, a := range args {
		if got.Arguments[i].Name != a.Name || got.Arguments[i].Value != a.Value {
			t.Fatalf("order[%d]=%+v want %+v", i, got.Arguments[i], a)
		}
		if i >= 3 && AccountingOnlyName(a.Name) {
			t.Fatalf("authorization arg %q classified as accounting-only", a.Name)
		}
	}
	if got.Command != "show running-config" {
		t.Fatalf("command=%q", got.Command)
	}
}

func TestCommandAccounting(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:    AcctFlagStop,
		UserID:   "lab-admin",
		ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: "configure"},
			{Name: "cmd-arg", Separator: '=', Value: "terminal"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ring.Latest()
	if got.Command != "configure terminal" {
		t.Fatalf("cmd=%q", got.Command)
	}
}

func TestAccountingDictionaryEncodings(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ok := domain.AVPairs{
		{Name: "task_id", Separator: '=', Value: "t"},
		{Name: "start_time", Separator: '=', Value: "1"},
		{Name: "stop_time", Separator: '=', Value: "2"},
		{Name: "elapsed_time", Separator: '=', Value: "1"},
		{Name: "timezone", Separator: '=', Value: "UTC"},
		{Name: "event", Separator: '=', Value: "acct_off"},
		{Name: "reason", Separator: '=', Value: "reload"},
		{Name: "bytes", Separator: '=', Value: "0"},
		{Name: "bytes_in", Separator: '=', Value: "1"},
		{Name: "bytes_out", Separator: '=', Value: "2"},
		{Name: "paks", Separator: '=', Value: "3"},
		{Name: "paks_in", Separator: '=', Value: "4"},
		{Name: "paks_out", Separator: '=', Value: "5"},
		{Name: "err_msg", Separator: '=', Value: "ok"},
	}
	if _, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags: AcctFlagStop, ClientID: "lab-switches", Arguments: ok,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := ring.Latest()
	if got.StartTime == nil || got.StopTime == nil {
		t.Fatalf("times not applied: %+v", got)
	}
	if got.StartTime.Location() != time.UTC {
		t.Fatalf("default timezone %v", got.StartTime.Location())
	}

	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStop,
		ClientID:  "lab-switches",
		Arguments: domain.AVPairs{{Name: "bytes", Separator: '=', Value: "nope"}},
	})
	if err == nil {
		t.Fatal("bad numeric")
	}

	_, err = svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStop,
		ClientID:  "lab-switches",
		Arguments: domain.AVPairs{{Name: "err_msg", Separator: '=', Value: "bad\x00msg"}},
	})
	if err == nil {
		t.Fatal("control in err_msg")
	}

	// Extensible event values.
	if _, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStart,
		ClientID:  "lab-switches",
		Arguments: domain.AVPairs{{Name: "event", Separator: '=', Value: "vendor_custom"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTimezoneAppliedToPacketTimes(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:    AcctFlagStop,
		ClientID: "lab-switches",
		Arguments: domain.AVPairs{
			{Name: "timezone", Separator: '=', Value: "-05:00"},
			{Name: "start_time", Separator: '=', Value: "3600"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ring.Latest()
	if got.StartTime == nil {
		t.Fatal("missing start")
	}
	if _, off := got.StartTime.Zone(); off != -5*3600 {
		t.Fatalf("offset=%d", off)
	}
}

func TestSuccessOnlyAfterRingAccept(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ring.SetReject(true)
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:    AcctFlagStart,
		ClientID: "lab-switches",
	})
	if err == nil || res.OK {
		t.Fatalf("rejected sink must ERROR: %+v %v", res, err)
	}
	if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInternal {
		t.Fatalf("err=%v", err)
	}
	if ring.Len() != 0 {
		t.Fatal("rejected record stored")
	}
}

func TestNilServiceAccounting(t *testing.T) {
	t.Parallel()
	var svc *Service
	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{Flags: AcctFlagStart})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanceledContextNoSuccess(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.RecordAccounting(ctx, AccountingRecord{Flags: AcctFlagStart, ClientID: "lab-switches"})
	if err == nil {
		t.Fatal("canceled ctx")
	}
	if ring.Len() != 0 {
		t.Fatal("canceled request stored")
	}
}

func TestTooManyAccountingArgs(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	args := make(domain.AVPairs, 257)
	for i := range args {
		args[i] = domain.AVPair{Name: "x", Separator: '=', Value: "1"}
	}
	_, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags: AcctFlagStart, ClientID: "lab-switches", Arguments: args,
	})
	if err == nil {
		t.Fatal("expected over-budget error")
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

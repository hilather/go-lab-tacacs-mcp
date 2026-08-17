package aaa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

func TestRecordRADIUSAccountingFeedsSessionIndex(t *testing.T) {
	t.Parallel()
	_, lookup, mgr := writeSkeleton(t, "")
	ring := events.New(32, domain.SystemClock{})
	idx, err := radiusruntime.NewSessionIndex(radiusruntime.Options{
		MaxEntries: 16,
		MaxBytes:   64 << 10,
		TTL:        time.Hour,
		Entropy:    bytes.NewReader(bytes.Repeat([]byte("0123456789abcdef"), 8)),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{Manager: mgr, Secrets: lookup, Events: ring, Creds: credentials.Options{Params: credentials.TestParams}, Sessions: idx})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Context: domain.RequestContext{
			Protocol:   domain.ProtocolRADIUS,
			ClientID:   "lab-switches",
			EndpointID: "acct-udp",
			Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
		},
		Kind:      AccountingStart,
		UserID:    "lab-admin",
		SessionID: "hook-sess-1",
		NASIP:     netip.MustParseAddr("192.0.2.10"),
	})
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	got, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "acct-udp", AcctSessionID: "hook-sess-1"})
	if !ok || got.UserID != "lab-admin" {
		t.Fatalf("index=%+v ok=%v", got, ok)
	}
	_, err = svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Context:   domain.RequestContext{EndpointID: "acct-udp", Peer: netip.MustParseAddrPort("192.0.2.10:1813")},
		Kind:      AccountingOn,
		SessionID: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "acct-udp", AcctSessionID: "hook-sess-1"}); ok {
		t.Fatal("Accounting-On must flush")
	}
}

func TestRecordRADIUSAccountingWritesRing(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	started := time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC)
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Context: domain.RequestContext{
			Protocol:         domain.ProtocolRADIUS,
			Carrier:          domain.CarrierRADIUSUDP,
			ListenerRole:     domain.RoleAccounting,
			ListenerID:       "radius-acct",
			ClientID:         "nas-1",
			EndpointID:       "nas-1-acct",
			Peer:             netip.MustParseAddrPort("192.0.2.10:1813"),
			SnapshotRevision: 3,
		},
		Kind:           AccountingStart,
		UserID:         "lab-admin",
		SessionID:      "nas-sess-aa11",
		StartedAt:      &started,
		InputOctets:    10,
		OutputOctets:   20,
		SafeAttributes: []SafeAttributeSummary{{Name: "NAS-IP-Address"}, {Name: "User-Name", Count: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.EventID == 0 {
		t.Fatalf("result=%+v", res)
	}
	got, ok := ring.Latest()
	if !ok || got.ID != res.EventID {
		t.Fatalf("ring=%+v ok=%v", got, ok)
	}
	if got.Category != events.CategoryAcct || got.Type != "start" || got.Result != "success" {
		t.Fatalf("identity=%+v", got)
	}
	if got.Protocol != "radius" || got.Carrier != "radius_udp" || got.ListenerRole != "accounting" {
		t.Fatalf("taxonomy=%+v", got)
	}
	if got.ListenerID != "radius-acct" || got.EndpointID != "nas-1-acct" || got.ClientID != "nas-1" {
		t.Fatalf("context=%+v", got)
	}
	if got.AcctSessionID != "nas-sess-aa11" {
		t.Fatalf("acct_session_id=%q", got.AcctSessionID)
	}
	if got.SessionID != 0 {
		t.Fatalf("TACACS SessionID must stay 0 for RADIUS, got %d", got.SessionID)
	}
	if got.UserID != "lab-admin" || got.Remote != "192.0.2.10:1813" || got.Revision != 3 {
		t.Fatalf("fields=%+v", got)
	}
	if got.StartTime == nil || !got.StartTime.Equal(started) {
		t.Fatalf("start=%v", got.StartTime)
	}
}

func TestRecordRADIUSAccountingDoesNotStuffSessionID(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	// Numeric and over-uint32 text must not be parsed into Event.SessionID.
	for _, sid := range []string{"42", "4294967296", "0x01020304", "nas-sess-9"} {
		res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
			Kind:      AccountingStop,
			UserID:    "lab-admin",
			SessionID: sid,
		})
		if err != nil || !res.OK {
			t.Fatalf("sid %q: %+v %v", sid, res, err)
		}
		got, _ := ring.Latest()
		if got.SessionID != 0 {
			t.Fatalf("sid %q stuffed into uint32 SessionID=%d", sid, got.SessionID)
		}
		if got.AcctSessionID != sid {
			t.Fatalf("sid %q stored as %q", sid, got.AcctSessionID)
		}
	}
}

func TestRecordRADIUSAccountingRedactsSensitiveAttributes(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	const (
		session = "acct-sess-should-not-appear-in-avs"
		user    = "radius-user-canary"
		secret  = "unit-test-user-password-canary-cc33"
	)
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Kind:      AccountingStop,
		UserID:    user,
		SessionID: session,
		SafeAttributes: []SafeAttributeSummary{
			{Name: "User-Password"},
			{Name: "CHAP-Password"},
			{Name: "Message-Authenticator"},
			{Name: "Acct-Session-Id"},
			{Name: "User-Name"},
			{Name: "Class"},
			{Name: "Calling-Station-Id"},
			{Name: "Vendor-Specific", Count: 2},
		},
	})
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := ring.Latest()
	if got.AcctSessionID != session {
		t.Fatalf("stored session %q", got.AcctSessionID)
	}
	if got.SessionID != 0 {
		t.Fatalf("session stuffed: %d", got.SessionID)
	}
	if len(got.Arguments) == 0 {
		t.Fatal("expected redacted attribute summaries")
	}
	var sawSessionAV, sawVendor bool
	for _, a := range got.Arguments {
		if a.Value != events.RedactedValue && !strings.HasPrefix(a.Name, "Acct-") {
			t.Fatalf("unredacted AV %+v", a)
		}
		if a.Name == "Acct-Session-Id" {
			sawSessionAV = true
			if a.Value != events.RedactedValue {
				t.Fatalf("Acct-Session-Id value=%q", a.Value)
			}
		}
		if a.Name == "Vendor-Specific#2" {
			sawVendor = true
		}
		if strings.Contains(a.Value, session) || strings.Contains(a.Value, user) || strings.Contains(a.Value, secret) {
			t.Fatalf("sensitive value leaked in AV %+v", a)
		}
	}
	if !sawSessionAV {
		t.Fatal("missing redacted Acct-Session-Id AV")
	}
	if !sawVendor {
		t.Fatal("count suffix missing")
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatalf("secret in event JSON: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"acct_session_id"`)) {
		t.Fatalf("acct_session_id omitted: %s", raw)
	}
	if bytes.Contains(raw, []byte(`"session_id"`)) {
		t.Fatalf("uint32 session_id present on RADIUS event: %s", raw)
	}
}

func TestRecordRADIUSAccountingAllKinds(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	kinds := []AccountingKind{AccountingStart, AccountingStop, AccountingInterim, AccountingOn, AccountingOff}
	for _, k := range kinds {
		if !k.Valid() {
			t.Fatalf("valid %q rejected", k)
		}
		res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{Kind: k, SessionID: "s"})
		if err != nil || !res.OK {
			t.Fatalf("kind %q: %+v %v", k, res, err)
		}
		got, _ := ring.Latest()
		if got.Type != k.String() {
			t.Fatalf("kind %q type=%q", k, got.Type)
		}
	}
	for _, bad := range []AccountingKind{"", "watchdog", "START", "interim"} {
		if bad.Valid() {
			t.Fatalf("invalid %q accepted", bad)
		}
		_, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{Kind: bad})
		if err == nil {
			t.Fatalf("kind %q should ERROR", bad)
		}
		if de, ok := domain.AsError(err); !ok || de.Code != domain.CodeInvalidArgument {
			t.Fatalf("kind %q err=%v", bad, err)
		}
	}
}

func TestRecordRADIUSAccountingRejectsNonRADIUSProtocol(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	_, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Context: domain.RequestContext{Protocol: domain.ProtocolTACACS},
		Kind:    AccountingStart,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if ring.Len() != 0 {
		t.Fatal("rejected record stored")
	}
}

func TestRecordRADIUSAccountingRejectsUnknownTerminateCause(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	_, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Kind:           AccountingStop,
		TerminateCause: "not-a-cause",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if ring.Len() != 0 {
		t.Fatal("rejected record stored")
	}
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Kind:           AccountingStop,
		TerminateCause: "user_request",
	})
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := ring.Latest()
	found := false
	for _, a := range got.Arguments {
		if a.Name == "Acct-Terminate-Cause" && a.Value == "User-Request" {
			found = true
		}
	}
	if !found {
		t.Fatalf("canonical cause missing: %+v", got.Arguments)
	}
}

func TestRecordRADIUSAccountingSuccessOnlyAfterRingAccept(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ring.SetReject(true)
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{Kind: AccountingStart})
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

func TestRecordRADIUSAccountingNilService(t *testing.T) {
	t.Parallel()
	var svc *Service
	_, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{Kind: AccountingStart})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRecordRADIUSAccountingCanceledContext(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.RecordRADIUSAccounting(ctx, RADIUSAccountingRecord{Kind: AccountingStart})
	if err == nil {
		t.Fatal("canceled ctx")
	}
	if ring.Len() != 0 {
		t.Fatal("canceled request stored")
	}
}

func TestRecordRADIUSAccountingTooManyAttributes(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	attrs := make([]SafeAttributeSummary, 257)
	for i := range attrs {
		attrs[i] = SafeAttributeSummary{Name: "NAS-Port"}
	}
	_, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Kind: AccountingStart, SafeAttributes: attrs,
	})
	if err == nil {
		t.Fatal("expected over-budget error")
	}
}

func TestTACACSAccountingSessionIDRemainsUint32(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	res, err := svc.RecordAccounting(context.Background(), AccountingRecord{
		Flags:     AcctFlagStart,
		UserID:    "lab-admin",
		ClientID:  "lab-switches",
		SessionID: 42,
	})
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := ring.Latest()
	if got.SessionID != 42 {
		t.Fatalf("TACACS SessionID=%d", got.SessionID)
	}
	if got.AcctSessionID != "" {
		t.Fatalf("TACACS event must omit AcctSessionID, got %q", got.AcctSessionID)
	}
	if got.Protocol != "" {
		t.Fatalf("TACACS event must omit Protocol, got %q", got.Protocol)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"acct_session_id"`)) || bytes.Contains(raw, []byte(`"protocol"`)) {
		t.Fatalf("TACACS JSON grew RADIUS fields: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"session_id"`)) {
		t.Fatalf("TACACS session_id missing: %s", raw)
	}
}

func TestRecordRADIUSAccountingIncludeAccountingFalseStillACKs(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	_, lookup, mgr := writeSkeleton(t, `
events:
  include_accounting: false
  stdout: {enabled: true, format: json}
`)
	ring := events.NewWithOptions(events.Options{Capacity: 32, Stdout: &stdout, RedactUserInput: true, StdoutBuffer: 8})
	t.Cleanup(ring.Close)
	svc, err := New(Options{
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Events:   ring,
		Creds:    credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{
		Kind:      AccountingStart,
		UserID:    "lab-admin",
		SessionID: "hidden-sess",
	})
	if err != nil || !res.OK || res.EventID == 0 {
		t.Fatalf("ACK required: %+v %v", res, err)
	}
	got, ok := ring.Latest()
	if !ok || !got.SuppressExport || got.ID != res.EventID {
		t.Fatalf("sink record=%+v ok=%v", got, ok)
	}
	page := ring.Read(events.Query{Limit: 10, Categories: []string{events.CategoryAcct}})
	if len(page.Items) != 0 {
		t.Fatalf("list should hide acct: %+v", page.Items)
	}
}

func TestRecordRADIUSAccountingDefaultsProtocolAndRole(t *testing.T) {
	t.Parallel()
	svc, _, ring := testService(t)
	if _, err := svc.RecordRADIUSAccounting(context.Background(), RADIUSAccountingRecord{Kind: AccountingOn}); err != nil {
		t.Fatal(err)
	}
	got, _ := ring.Latest()
	if got.Protocol != "radius" || got.ListenerRole != "accounting" {
		t.Fatalf("defaults=%+v", got)
	}
}

package udp

import (
	"context"
	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type gatedAccountingSink struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	fail    atomic.Bool
}

func (s *gatedAccountingSink) RecordRADIUSAccounting(ctx context.Context, _ aaa.RADIUSAccountingRecord) (aaa.AccountingResult, error) {
	n := s.calls.Add(1)
	if n == 1 {
		close(s.started)
	}
	select {
	case <-s.release:
	case <-ctx.Done():
		return aaa.AccountingResult{}, ctx.Err()
	}
	if s.fail.Load() {
		return aaa.AccountingResult{}, nil
	}
	return aaa.AccountingResult{OK: true, EventID: uint64(n)}, nil
}
func semanticAccountingRequest(t *testing.T, j server.SemanticJournal, id uint8) server.Request {
	t.Helper()
	secret := []byte("semantic-test-shared-secret")
	wire, err := testclient.EncodeAccountingRequest(secret, testclient.AccountingRequest{Identifier: id, StatusType: 1, SessionID: "session", Extra: []tcodec.Attr{{Type: 41, Value: []byte{0, 0, 0, id}}}})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	return server.Request{Role: domain.RoleAccounting, Carrier: domain.CarrierRADIUSUDP, Packet: pkt, Declared: wire, Secret: secret, EndpointID: "ep", Peer: netip.MustParseAddrPort("192.0.2.1:1234"), Journal: j}
}

type observedSemanticJournal struct {
	*journal
	attempts atomic.Int32
	second   chan struct{}
}

func (j *observedSemanticJournal) Begin(ctx context.Context, key server.JournalKey) (bool, bool, error) {
	if j.attempts.Add(1) == 2 {
		close(j.second)
	}
	return j.journal.Begin(ctx, key)
}

// This old-interface hook also makes the pre-fix regression deterministic:
// the second miss is known before the test releases the first sink call.
func (j *observedSemanticJournal) Seen(key server.JournalKey) bool {
	found := j.journal.Seen(key)
	if j.attempts.Add(1) == 2 {
		close(j.second)
	}
	return found
}

func TestAccountingSemanticReservationConcurrent(t *testing.T) {
	j := &observedSemanticJournal{journal: newJournal(8, 4096, time.Minute, time.Now), second: make(chan struct{})}
	sink := &gatedAccountingSink{started: make(chan struct{}), release: make(chan struct{})}
	h := server.Accounting{AAA: sink}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first := semanticAccountingRequest(t, j, 1)
	second := semanticAccountingRequest(t, j, 2)
	out := make(chan server.Result, 2)
	go func() { out <- h.Handle(ctx, first) }()
	<-sink.started
	go func() { out <- h.Handle(ctx, second) }()
	select {
	case <-j.second:
	case <-ctx.Done():
		t.Fatal("retry never entered semantic journal")
	}
	close(sink.release)
	for range 2 {
		res := <-out
		if res.Action != server.ActionReply {
			t.Fatalf("reply: %+v", res)
		}
		var req server.Request
		if res.Response[1] == 1 {
			req = first
		} else {
			req = second
		}
		if _, err := testclient.DecodeAccountingResponse(req.Secret, req.Packet.Authenticator, res.Response); err != nil {
			t.Fatal(err)
		}
	}
	if n := sink.calls.Load(); n != 1 {
		t.Fatalf("semantic retry appended %d events", n)
	}
}
func TestAccountingSemanticReservationFailureRetryAndCancellation(t *testing.T) {
	j := newJournal(1, 4096, time.Minute, time.Now)
	key := server.JournalKey{EndpointID: "ep"}
	owner, full, err := j.Begin(context.Background(), key)
	if !owner || full || err != nil {
		t.Fatal("reserve")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := j.Begin(ctx, key); err == nil {
		t.Fatal("pending wait ignored cancellation")
	}
	_, full, err = j.Begin(context.Background(), server.JournalKey{EndpointID: "other"})
	if !full || err != nil {
		t.Fatal("pending row not charged to capacity")
	}
	j.Finish(key, false)
	owner, full, err = j.Begin(context.Background(), key)
	if !owner || full || err != nil {
		t.Fatal("failed sink poisoned retry")
	}
	j.Finish(key, true)
	owner, _, err = j.Begin(context.Background(), key)
	if owner || err != nil {
		t.Fatal("completed retry not deduplicated")
	}
}

func TestAccountingRejectedSinkReservationCanRetry(t *testing.T) {
	j := newJournal(8, 4096, time.Minute, time.Now)
	sink := &gatedAccountingSink{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	sink.fail.Store(true)
	h := server.Accounting{AAA: sink}
	if got := h.Handle(context.Background(), semanticAccountingRequest(t, j, 1)); got.Action != server.ActionDiscard {
		t.Fatal("failed sink acknowledged")
	}
	sink.fail.Store(false)
	req := semanticAccountingRequest(t, j, 2)
	got := h.Handle(context.Background(), req)
	if got.Action != server.ActionReply || sink.calls.Load() != 2 {
		t.Fatal("failed sink poisoned retry")
	}
	if _, err := testclient.DecodeAccountingResponse(req.Secret, req.Packet.Authenticator, got.Response); err != nil {
		t.Fatal(err)
	}
	if got := h.Handle(context.Background(), semanticAccountingRequest(t, j, 3)); got.Action != server.ActionReply || sink.calls.Load() != 2 {
		t.Fatal("accepted retry not committed")
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

type memJournal struct {
	mu   sync.Mutex
	seen map[JournalKey]struct{}
	full bool
	n    int
}

func (j *memJournal) Seen(k JournalKey) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.seen[k]
	return ok
}

func (j *memJournal) Remember(k JournalKey) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.full {
		return false
	}
	if j.seen == nil {
		j.seen = map[JournalKey]struct{}{}
	}
	j.seen[k] = struct{}{}
	j.n++
	return true
}

type allowN struct {
	mu    sync.Mutex
	left  int
	calls int
}

func (a *allowN) Allow() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.left <= 0 {
		return false
	}
	a.left--
	return true
}

type recSink struct {
	mu      sync.Mutex
	records []aaa.RADIUSAccountingRecord
	reject  bool
}

func (s *recSink) RecordRADIUSAccounting(_ context.Context, rec aaa.RADIUSAccountingRecord) (aaa.AccountingResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reject {
		return aaa.AccountingResult{}, nil
	}
	s.records = append(s.records, rec)
	return aaa.AccountingResult{OK: true, EventID: uint64(len(s.records))}, nil
}

func (s *recSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *recSink) last() aaa.RADIUSAccountingRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[len(s.records)-1]
}

func uint32Raw(typ uint8, v uint32) attribute.Raw {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return attribute.Raw{Type: typ, Value: b[:]}
}

func signAcct(t *testing.T, secret []byte, id uint8, attrs attribute.RawSet) (codec.Packet, []byte) {
	t.Helper()
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: id, Attributes: attrs}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	declared, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return pkt, declared
}

func signAcctMA(t *testing.T, secret []byte, id uint8, attrs attribute.RawSet) (codec.Packet, []byte) {
	t.Helper()
	withMA := attrs.Clone()
	withMA = append(withMA, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)})
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: id, Attributes: withMA}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	raw, err = codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := crypto.MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Attributes[len(pkt.Attributes)-1].Value = append([]byte(nil), mac[:]...)
	declared, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return pkt, declared
}

func acctReq(role domain.ListenerRole, pkt codec.Packet, declared []byte, j SemanticJournal, samp AmbiguousSampler) Request {
	return Request{
		Role:       role,
		Packet:     pkt,
		Declared:   declared,
		Secret:     testSecret,
		ClientID:   "loop",
		EndpointID: "radius-udp",
		Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
		ListenerID: "radius_accounting",
		Journal:    j,
		Sampler:    samp,
	}
}

func TestAccountingFiveStatusTypes(t *testing.T) {
	t.Parallel()
	kinds := []struct {
		n    uint32
		want aaa.AccountingKind
	}{
		{1, aaa.AccountingStart},
		{2, aaa.AccountingStop},
		{3, aaa.AccountingInterim},
		{7, aaa.AccountingOn},
		{8, aaa.AccountingOff},
	}
	sink := &recSink{}
	j := &memJournal{}
	h := Accounting{AAA: sink}
	for i, tc := range kinds {
		pkt, raw := signAcct(t, testSecret, uint8(i+1), attribute.RawSet{
			uint32Raw(attribute.TypeAcctStatusType, tc.n),
			{Type: attribute.TypeAcctSessionID, Value: []byte("s")},
		})
		res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, j, nil))
		if res.Action != ActionReply || res.Reason != ReasonOK {
			t.Fatalf("kind %d: %+v", tc.n, res)
		}
		assertSigned(t, res.Response, codec.CodeAccountingResponse, uint8(i+1), pkt.Authenticator, testSecret)
		if sink.last().Kind != tc.want {
			t.Fatalf("kind %d stored %q", tc.n, sink.last().Kind)
		}
	}
	if sink.len() != 5 {
		t.Fatalf("records=%d", sink.len())
	}
}

func TestAccountingValidatesRequestAuthenticator(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	h := Accounting{AAA: sink}
	pkt, raw := signAcct(t, testSecret, 4, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("s")},
	})
	pkt.Authenticator[0] ^= 0xff
	bad, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, bad, nil, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidAcctAuth {
		t.Fatalf("got %+v", res)
	}
	if sink.len() != 0 {
		t.Fatal("side effect after bad authenticator")
	}
	_ = raw
}

func TestAccountingMAValidateIfPresent(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	h := Accounting{AAA: sink}
	j := &memJournal{}
	base := attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("ma-sess")},
	}

	pkt, raw := signAcct(t, testSecret, 1, base)
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, j, nil))
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("missing MA must be accepted: %+v", res)
	}

	pktMA, rawMA := signAcctMA(t, testSecret, 2, base)
	res = h.Handle(context.Background(), acctReq(domain.RoleAccounting, pktMA, rawMA, j, nil))
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("valid MA must be accepted: %+v", res)
	}

	badPkt := pktMA
	badPkt.Attributes[len(badPkt.Attributes)-1].Value[0] ^= 0xff
	badRaw, err := codec.Encode(badPkt)
	if err != nil {
		t.Fatal(err)
	}
	before := sink.len()
	res = h.Handle(context.Background(), acctReq(domain.RoleAccounting, badPkt, badRaw, j, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidMA {
		t.Fatalf("invalid MA: %+v", res)
	}
	if sink.len() != before {
		t.Fatal("invalid MA recorded")
	}

	dup := base.Clone()
	dup = append(dup,
		attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
	)
	dupPkt, dupRaw := signAcct(t, testSecret, 3, dup)
	res = h.Handle(context.Background(), acctReq(domain.RoleAccounting, dupPkt, dupRaw, j, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidMA {
		t.Fatalf("duplicate MA: %+v", res)
	}
}

func TestAccountingUnknownAndAllowlistedStatus(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	h := Accounting{AAA: sink}
	j := &memJournal{}

	pkt, raw := signAcct(t, testSecret, 1, nil)
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, j, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonUnknownAcctStatus {
		t.Fatalf("missing status: %+v", res)
	}

	pkt, raw = signAcct(t, testSecret, 2, attribute.RawSet{uint32Raw(attribute.TypeAcctStatusType, 99)})
	res = h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, j, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonUnknownAcctStatus {
		t.Fatalf("unknown status: %+v", res)
	}

	pkt, raw = signAcct(t, testSecret, 3, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("s")},
	})
	in := acctReq(domain.RoleAccounting, pkt, raw, j, nil)
	in.AcceptStatusTypes = []string{"stop"}
	res = h.Handle(context.Background(), in)
	if res.Action != ActionDiscard || res.Reason != ReasonUnknownAcctStatus {
		t.Fatalf("not allowlisted: %+v", res)
	}
	if sink.len() != 0 {
		t.Fatal("discard recorded")
	}
}

func TestAccountingJournalHitDoesNotRerecord(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	j := &memJournal{}
	h := Accounting{AAA: sink}
	attrs := attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("same")},
		uint32Raw(attribute.TypeAcctDelayTime, 0),
	}
	pkt1, raw1 := signAcct(t, testSecret, 1, attrs)
	res1 := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt1, raw1, j, nil))
	if res1.Action != ActionReply || sink.len() != 1 {
		t.Fatalf("first %+v n=%d", res1, sink.len())
	}

	delayed := attrs.Clone()
	delayed[2] = uint32Raw(attribute.TypeAcctDelayTime, 5)
	pkt2, raw2 := signAcct(t, testSecret, 2, delayed)
	res2 := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt2, raw2, j, nil))
	if res2.Action != ActionReply || res2.Reason != ReasonOK {
		t.Fatalf("delay-time retry %+v", res2)
	}
	if sink.len() != 1 {
		t.Fatalf("delay-time must not record again, n=%d", sink.len())
	}
	if bytes.Equal(res1.Response, res2.Response) {
		t.Fatal("new Identifier must produce a new Accounting-Response")
	}
	assertSigned(t, res2.Response, codec.CodeAccountingResponse, 2, pkt2.Authenticator, testSecret)
}

func TestAccountingInterimNotCollapsed(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	j := &memJournal{}
	h := Accounting{AAA: sink}
	base := func(octets uint32) attribute.RawSet {
		return attribute.RawSet{
			uint32Raw(attribute.TypeAcctStatusType, 3),
			{Type: attribute.TypeAcctSessionID, Value: []byte("int")},
			uint32Raw(attribute.TypeAcctInputOctets, octets),
		}
	}
	pkt1, raw1 := signAcct(t, testSecret, 1, base(10))
	pkt2, raw2 := signAcct(t, testSecret, 2, base(20))
	if res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt1, raw1, j, nil)); res.Action != ActionReply {
		t.Fatalf("%+v", res)
	}
	if res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt2, raw2, j, nil)); res.Action != ActionReply {
		t.Fatalf("%+v", res)
	}
	if sink.len() != 2 {
		t.Fatalf("interim counters must not collapse, n=%d", sink.len())
	}
}

func TestAccountingRingRejectSendsNoResponse(t *testing.T) {
	t.Parallel()
	sink := &recSink{reject: true}
	h := Accounting{AAA: sink}
	pkt, raw := signAcct(t, testSecret, 1, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("s")},
	})
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, &memJournal{}, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonInternal {
		t.Fatalf("got %+v", res)
	}
	if len(res.Response) != 0 {
		t.Fatal("no Accounting-Response after sink reject")
	}
}

func TestAccountingAmbiguousIdentitySampled(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	j := &memJournal{}
	samp := &allowN{left: 1}
	h := Accounting{AAA: sink}
	attrs := attribute.RawSet{uint32Raw(attribute.TypeAcctStatusType, 7)}
	pkt1, raw1 := signAcct(t, testSecret, 1, attrs)
	res1 := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt1, raw1, j, samp))
	if res1.Action != ActionReply || res1.Reason != ReasonOK || sink.len() != 1 {
		t.Fatalf("first ambiguous should record: %+v n=%d", res1, sink.len())
	}
	pkt2, raw2 := signAcct(t, testSecret, 2, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 8),
	})
	res2 := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt2, raw2, j, samp))
	if res2.Action != ActionReply || res2.Reason != ReasonAmbiguousIdentity {
		t.Fatalf("over budget must still ACK: %+v", res2)
	}
	if sink.len() != 1 {
		t.Fatalf("over-budget recorded n=%d", sink.len())
	}
}

func TestAccountingGigawordFoldAndTerminateCause(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	h := Accounting{AAA: sink}
	pkt, raw := signAcct(t, testSecret, 1, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 2),
		{Type: attribute.TypeAcctSessionID, Value: []byte("stop-1")},
		{Type: attribute.TypeUserName, Value: []byte("alice")},
		uint32Raw(attribute.TypeAcctInputOctets, 10),
		uint32Raw(attribute.TypeAcctInputGigawords, 1),
		uint32Raw(attribute.TypeAcctOutputOctets, 20),
		uint32Raw(attribute.TypeAcctTerminateCause, 1),
		uint32Raw(attribute.TypeAcctSessionTime, 15),
	})
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, &memJournal{}, nil))
	if res.Action != ActionReply {
		t.Fatalf("%+v", res)
	}
	got := sink.last()
	if got.InputOctets != (1<<32)+10 || got.OutputOctets != 20 {
		t.Fatalf("octets in=%d out=%d", got.InputOctets, got.OutputOctets)
	}
	if got.TerminateCause != "User-Request" || got.UserID != "alice" {
		t.Fatalf("fields=%+v", got)
	}
	if got.SessionTime.Seconds() != 15 {
		t.Fatalf("session_time=%s", got.SessionTime)
	}
}

func BenchmarkAccountingHandle(b *testing.B) {
	sink := &recSink{}
	h := Accounting{AAA: sink}
	j := &memJournal{}
	pkt := codec.Packet{
		Code:       codec.CodeAccountingRequest,
		Identifier: 1,
		Attributes: attribute.RawSet{
			uint32Raw(attribute.TypeAcctStatusType, 1),
			{Type: attribute.TypeAcctSessionID, Value: []byte("bench")},
		},
	}
	raw, err := codec.Encode(pkt)
	if err != nil {
		b.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(testSecret, raw)
	if err != nil {
		b.Fatal(err)
	}
	pkt.Authenticator = auth
	raw, err = codec.Encode(pkt)
	if err != nil {
		b.Fatal(err)
	}
	in := acctReq(domain.RoleAccounting, pkt, raw, j, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Packet.Identifier = uint8(i)
		_ = h.Handle(context.Background(), in)
	}
}

func TestAccountingWrongRole(t *testing.T) {
	t.Parallel()
	h := Accounting{AAA: &recSink{}}
	pkt, raw := signAcct(t, testSecret, 1, attribute.RawSet{uint32Raw(attribute.TypeAcctStatusType, 1)})
	res := h.Handle(context.Background(), acctReq(domain.RoleAccess, pkt, raw, nil, nil))
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidCode {
		t.Fatalf("%+v", res)
	}
}

func TestAccountingJournalSaturatedStillRecords(t *testing.T) {
	t.Parallel()
	sink := &recSink{}
	j := &memJournal{full: true}
	h := Accounting{AAA: sink}
	pkt, raw := signAcct(t, testSecret, 1, attribute.RawSet{
		uint32Raw(attribute.TypeAcctStatusType, 1),
		{Type: attribute.TypeAcctSessionID, Value: []byte("s")},
	})
	res := h.Handle(context.Background(), acctReq(domain.RoleAccounting, pkt, raw, j, nil))
	if res.Action != ActionReply || !res.JournalSaturated || sink.len() != 1 {
		t.Fatalf("%+v n=%d", res, sink.len())
	}
}

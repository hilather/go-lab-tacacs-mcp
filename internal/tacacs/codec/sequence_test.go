package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestSequenceHappyPathAndParity(t *testing.T) {
	t.Parallel()
	s := NewSequence(0x01020304, TypeAuthen)
	req := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 0x01020304}
	if err := s.CheckRequest(req); err != nil {
		t.Fatal(err)
	}
	rep, err := s.NextReply(FlagSingleConnect)
	if err != nil || rep.SeqNo != 2 || !ServerSeq(rep.SeqNo) {
		t.Fatalf("reply %#v err=%v", rep, err)
	}
	req.SeqNo = 3
	if err := s.CheckRequest(req); err != nil {
		t.Fatal(err)
	}
	if ClientSeq(0) || ServerSeq(0) || !ClientSeq(1) || !ServerSeq(2) {
		t.Fatal("parity helpers")
	}
}

func TestSequenceRejectsWrongOrder(t *testing.T) {
	t.Parallel()
	s := NewSequence(1, TypeAuthen)
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 2, SessionID: 1}
	if err := s.CheckRequest(h); !errors.Is(err, ErrSeqParity) {
		t.Fatalf("even: %v", err)
	}
	h.SeqNo = 3
	if err := s.CheckRequest(h); !errors.Is(err, ErrSeqUnexpected) {
		t.Fatalf("skip: %v", err)
	}
	h.SeqNo = 1
	h.Type = TypeAuthor
	if err := s.CheckRequest(h); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("type: %v", err)
	}
}

func TestSequencePrematureSecondPacket(t *testing.T) {
	t.Parallel()
	s := NewSequence(1, TypeAuthen)
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 1}
	if err := s.CheckRequest(h); err != nil {
		t.Fatal(err)
	}
	h.SeqNo = 3
	if err := s.CheckRequest(h); !errors.Is(err, ErrPrematurePacket) {
		t.Fatalf("premature: %v", err)
	}
}

func TestSequenceWrap(t *testing.T) {
	t.Parallel()
	s := NewSequence(1, TypeAuthen)
	s.next = 255
	s.started = true
	s.replied = true
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 255, SessionID: 1}
	if err := s.CheckRequest(h); err != nil {
		t.Fatalf("seq 255 is legal: %v", err)
	}
	if _, err := s.NextReply(0); !errors.Is(err, ErrSeqWrap) {
		t.Fatalf("server wrap: %v", err)
	}
	if !s.Closed() {
		t.Fatal("wrap must close the session")
	}
}

func TestSequenceAuthorClosesAfterReply(t *testing.T) {
	t.Parallel()
	s := NewSequence(9, TypeAuthor)
	h := Header{Version: 0xc0, Type: TypeAuthor, SeqNo: 1, SessionID: 9}
	if err := s.CheckRequest(h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextReply(0); err != nil {
		t.Fatal(err)
	}
	if !s.Closed() {
		t.Fatal("author session should close after reply")
	}
}

func TestSequenceContinueLimit(t *testing.T) {
	t.Parallel()
	s := NewSequence(1, TypeAuthen)
	s.SetMaxContinues(1)
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 1}
	if err := s.CheckRequest(h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextReply(0); err != nil {
		t.Fatal(err)
	}
	h.SeqNo = 3
	if err := s.CheckRequest(h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextReply(0); err != nil {
		t.Fatal(err)
	}
	h.SeqNo = 5
	if err := s.CheckRequest(h); !errors.Is(err, ErrTooManyContinues) {
		t.Fatalf("limit: %v", err)
	}
}

func TestSingleConnectNegotiation(t *testing.T) {
	t.Parallel()
	var sc SingleConnect
	sc.OnClientFirst(FlagSingleConnect)
	if !sc.Pending() {
		t.Fatal("pending")
	}
	if err := sc.AllowNewSession(); !errors.Is(err, ErrPrematurePacket) {
		t.Fatalf("guard: %v", err)
	}
	if !sc.OnServerFirst(FlagSingleConnect) || !sc.Negotiated() {
		t.Fatal("both flags")
	}
	if err := sc.AllowNewSession(); err != nil {
		t.Fatal(err)
	}
	// later flags ignored
	sc.OnClientFirst(0)
	if !sc.Negotiated() {
		t.Fatal("later client flag changed result")
	}
	if NegotiateSingleConnect(false, FlagSingleConnect, FlagSingleConnect) {
		t.Fatal("after first pair")
	}
	if !NegotiateSingleConnect(true, FlagSingleConnect, FlagSingleConnect) {
		t.Fatal("first pair")
	}
}

func TestNewSessionID(t *testing.T) {
	t.Parallel()
	id, err := NewSessionID(bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil || id != 0x01020304 {
		t.Fatalf("id=%#x err=%v", id, err)
	}
	if _, err := NewSessionID(bytes.NewReader(nil)); !errors.Is(err, ErrEntropy) {
		t.Fatalf("short: %v", err)
	}
	// Encode must not invent a session id.
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 0xaabbccdd}
	if DecodeMustSession(t, h.Encode()) != 0xaabbccdd {
		t.Fatal("session id overwritten")
	}
}

func DecodeMustSession(t *testing.T, raw []byte) uint32 {
	t.Helper()
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h.SessionID
}

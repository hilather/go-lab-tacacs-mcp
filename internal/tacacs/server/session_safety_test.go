package server

import (
	"context"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	"sync"
	"testing"
)

func TestNonSingleConnectRejectsSecondLiveSession(t *testing.T) {
	client, _ := netPipeServe(t, testLimits(), getUserStub{})
	defer client.Close()
	first := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, SessionID: 1}
	if err := writePacket(client, first, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(client); err != nil {
		t.Fatal(err)
	}
	second := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 2}
	if err := writePacket(client, second, authorBody("unnegotiated")); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := codec.DecodeAuthorResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Status != codec.AuthorStatusError {
		t.Fatalf("second session dispatched without negotiation: status=%x", reply.Status)
	}
}

func TestSessionStopDoesNotRaceSequenceOwner(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := newSession(1, codec.TypeAuthen)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; s.stop() }()
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				_ = s.seq.Closed()
			}
		}()
		close(start)
		wg.Wait()
	}
}

type stoppedSessionProbe struct {
	Stub
	calls int
}

func (p *stoppedSessionProbe) Authorize(context.Context, Env, codec.AuthorRequest) (codec.AuthorResponse, error) {
	p.calls++
	return codec.AuthorResponse{Status: codec.AuthorStatusFail}, nil
}

func TestStoppedQueuedSessionNeverDispatches(t *testing.T) {
	p := &stoppedSessionProbe{}
	cs := &connState{h: p, sessions: make(map[uint32]*session)}
	cs.closed.Store(true)
	for i := 0; i < 100; i++ {
		s := newSession(1, codec.TypeAuthor)
		s.in <- packet{hdr: codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 1}, body: authorBody("stopped")}
		s.stop()
		cs.wg.Add(1)
		cs.runSession(context.Background(), s)
	}
	if p.calls != 0 {
		t.Fatalf("stopped queued session dispatched %d requests", p.calls)
	}
}

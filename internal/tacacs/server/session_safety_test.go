package server

import (
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

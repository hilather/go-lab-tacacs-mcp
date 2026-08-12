package server

import (
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestConcurrentSingleConnectSessions(t *testing.T) {
	client, done := startServe(testLimits())
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(client, h, authorBody("seed")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(client); err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(sid uint32) {
			defer wg.Done()
			req := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: sid}
			if err := writePacket(client, req, authorBody("u")); err != nil {
				errc <- err
				return
			}
		}(uint32(100 + i))
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		_, body, err := readPacket(client)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		rep, err := codec.DecodeAuthorResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Status != codec.AuthorStatusFail {
			t.Fatalf("status=%#x", rep.Status)
		}
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

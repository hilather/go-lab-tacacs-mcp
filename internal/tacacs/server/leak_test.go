package server

import (
	"runtime"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestServeConnNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		client, done := startServe(testLimits())
		h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: uint32(i + 1)}
		if err := writePacket(client, h, authorBody("leak")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readPacket(client); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server stuck")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		runtime.GC()
		n = runtime.NumGoroutine()
		if n <= base+8 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: have %d baseline %d", n, base)
}

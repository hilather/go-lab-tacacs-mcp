package server

import (
	"testing"
	"time"
)

func FuzzServeConn(f *testing.F) {
	f.Add([]byte{0xc0, 0x02, 0x01, 0x00, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2048 {
			raw = raw[:2048]
		}
		lim := testLimits()
		lim.HandshakeTimeout = 50 * time.Millisecond
		lim.ReadTimeout = 50 * time.Millisecond
		lim.IdleTimeout = 50 * time.Millisecond
		lim.ShutdownGrace = 50 * time.Millisecond
		client, done := startServe(lim)
		_, _ = client.Write(raw)
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ServeConn hung")
		}
	})
}

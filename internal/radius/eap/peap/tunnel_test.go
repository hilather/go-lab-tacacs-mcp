package peap

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestTunnelHandshakeProducesTLS13ServerRecords(t *testing.T) {
	t.Parallel()
	s, err := NewServer(mustPEAPCert(t))
	if err != nil {
		t.Fatal(err)
	}
	tun, err := s.NewTunnel()
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	peerIn, peerOut := newBytePipe(), newBytePipe()
	peer := tls.Client(&duplex{r: peerIn, w: peerOut}, &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ServerName:             "peap.lab.example",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	})
	errc := make(chan error, 1)
	go func() { errc <- peer.Handshake() }()

	hello := waitTake(t, peerOut, time.Second)
	if len(hello) < 1 || hello[0] != 0x16 {
		t.Fatalf("client hello %x", hello[:min(8, len(hello))])
	}
	if err := tun.PushClient(hello); err != nil {
		t.Fatal(err)
	}
	tun.WaitProgress(2 * time.Second)
	srv := tun.PullServer()
	if len(srv) < 1 || srv[0] != 0x16 {
		t.Fatalf("server flight %x", srv[:min(8, len(srv))])
	}
	if _, err := peerIn.Write(srv); err != nil {
		t.Fatal(err)
	}
	// Finish the handshake: drain both sides until both report complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !(tun.HandshakeComplete() && peer.ConnectionState().HandshakeComplete) {
		if rec := tun.PullServer(); len(rec) > 0 {
			_, _ = peerIn.Write(rec)
		}
		if rec := peerOut.Take(); len(rec) > 0 {
			_ = tun.PushClient(rec)
		}
		if tun.HandshakeComplete() && peer.ConnectionState().HandshakeComplete {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer handshake timeout")
	}
	if !tun.HandshakeComplete() {
		t.Fatalf("server handshake: %v", tun.HandshakeErr())
	}

	inner := IdentityRequest(1)
	if err := tun.WriteApp(inner); err != nil {
		t.Fatal(err)
	}
	appRec := waitTake(t, tun.out, time.Second)
	if len(appRec) < 1 || appRec[0] != 0x17 {
		t.Fatalf("want TLS app data, got %x", appRec[:min(8, len(appRec))])
	}
}

func waitTake(t *testing.T, p *bytePipe, d time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if rec := p.Take(); len(rec) > 0 {
			return rec
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timeout waiting for TLS records")
	return nil
}

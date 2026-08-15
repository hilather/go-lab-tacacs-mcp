package udp

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func BenchmarkRadiusRetransmissionCacheHit(b *testing.B) {
	BenchmarkCacheHit(b)
}

func BenchmarkRadiusUDPDispatch_Parallel(b *testing.B) {
	dir := b.TempDir()
	sec := writeSecret(b, dir)
	doc, err := config.Parse([]byte(radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0")))
	if err != nil {
		b.Fatal(err)
	}
	ln := startAccessB(b, doc, server.Stub{})
	addr := ln.Addr().String()
	secret := []byte(labSecret)
	var ra [16]byte
	ra[0] = 0x42
	req := signAccessRequest(b, secret, codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    1,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("alice")},
		},
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			b.Fatal(err)
		}
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		buf := make([]byte, 4096)
		for pb.Next() {
			if _, err := c.Write(req); err != nil {
				b.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(buf); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func startAccessB(b *testing.B, doc *config.Document, h server.Handler) *Listener {
	b.Helper()
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		b.Fatal(err)
	}
	settings := doc.Listeners.RADIUSAccess
	settings.Workers = 8
	settings.QueueCapacity = 2048
	settings.WorkerDeadline = 2 * time.Second
	settings.PerSourceRate = 1e9
	settings.PerSourceBurst = 1_000_000
	ln, err := Listen(Options{
		Role:     domain.RoleAccess,
		Bind:     "127.0.0.1:0",
		Required: true,
		Settings: settings,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Handler:  h,
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ln.Ready() {
			b.Cleanup(func() {
				cancel()
				_ = ln.Drain(context.Background())
				_ = ln.Close()
				select {
				case <-errc:
				case <-time.After(2 * time.Second):
				}
			})
			return ln
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	_ = ln.Close()
	b.Fatal("listener not ready")
	return ln
}

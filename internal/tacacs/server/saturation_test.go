package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

func TestEngineConnectionSaturation(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry()
	e := &Engine{
		Limits:   Limits{MaxConnections: 2, ShutdownGrace: time.Second},
		Handler:  Stub{},
		Metrics:  observability.NewRecorder(reg),
		Listener: observability.ListenerLegacy,
	}
	e.Prepare()
	if !e.TryAcquire() || !e.TryAcquire() {
		t.Fatal("expected two slots")
	}
	if e.TryAcquire() {
		t.Fatal("cap should reject")
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	err := e.Serve(context.Background(), &pipeIO{nc: a}, testIdentity())
	if !errors.Is(err, ErrConnLimit) {
		t.Fatalf("err=%v", err)
	}
	e.Release()
	if !e.TryAcquire() {
		t.Fatal("release should free")
	}
	e.Release()
	e.Release()
}

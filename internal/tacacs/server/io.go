package server

import (
	"context"
	"net"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

// PacketIO is the per-connection transport. Legacy adapters deobfuscate on
// Read and obfuscate on Write; TLS adapters pass clear bodies.
type PacketIO interface {
	Read(ctx context.Context, maxBody uint32, deadline time.Time) (codec.Header, []byte, error)
	Write(ctx context.Context, h codec.Header, body []byte, deadline time.Time) error
	Close() error
	RemoteAddr() net.Addr
}

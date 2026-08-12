package tls

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

// conn is a PacketIO that requires TAC_PLUS_UNENCRYPTED_FLAG and never
// applies RFC 8907 obfuscation.
type conn struct {
	nc net.Conn
}

func newConn(nc net.Conn) *conn { return &conn{nc: nc} }

func (c *conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

func (c *conn) Close() error { return c.nc.Close() }

func (c *conn) Read(ctx context.Context, maxBody uint32, deadline time.Time) (codec.Header, []byte, error) {
	if err := ctx.Err(); err != nil {
		return codec.Header{}, nil, err
	}
	if err := c.nc.SetReadDeadline(deadline); err != nil {
		return codec.Header{}, nil, err
	}
	var raw [codec.HeaderSize]byte
	if _, err := io.ReadFull(c.nc, raw[:]); err != nil {
		return codec.Header{}, nil, err
	}
	h, err := codec.DecodeHeader(raw[:])
	if err != nil {
		return codec.Header{}, nil, err
	}
	if h.Flags&codec.FlagUnencrypted == 0 {
		if err := skipBody(c.nc, h, maxBody); err != nil {
			return h, nil, err
		}
		return h, nil, server.ErrMissingUnencrypted
	}
	body, err := h.AllocateBody(maxBody)
	if err != nil {
		return h, nil, err
	}
	if len(body) == 0 {
		return h, body, nil
	}
	if _, err := io.ReadFull(c.nc, body); err != nil {
		return h, nil, err
	}
	return h, body, nil
}

func (c *conn) Write(ctx context.Context, h codec.Header, body []byte, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.Flags |= codec.FlagUnencrypted
	h.Length = uint32(len(body))
	pkt := append(h.Encode(), body...)
	if err := c.nc.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := c.nc.Write(pkt)
	return err
}

func skipBody(r io.Reader, h codec.Header, maxBody uint32) error {
	max := codec.ClampMaxBody(maxBody)
	if h.Length > max {
		return codec.ErrBodyTooLarge
	}
	if h.Length == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(h.Length))
	return err
}

var _ server.PacketIO = (*conn)(nil)

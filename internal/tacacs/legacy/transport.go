package legacy

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

// conn is a PacketIO that deobfuscates inbound bodies and obfuscates
// outbound bodies with the bound shared secret.
type conn struct {
	nc     net.Conn
	secret credentials.SharedSecret
}

func newConn(nc net.Conn, secret credentials.SharedSecret) *conn {
	return &conn{nc: nc, secret: secret}
}

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
	if h.Flags&codec.FlagUnencrypted != 0 {
		// Skip the claimed body so a drain-and-continue read stays aligned.
		if err := skipBody(c.nc, h, maxBody); err != nil {
			return h, nil, err
		}
		return h, nil, server.ErrUnencrypted
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
	key := c.secret.Bytes()
	clear := codec.Obfuscate(h.SessionID, h.Version, h.SeqNo, key, body)
	wipe(key)
	return h, clear, nil
}

func (c *conn) Write(ctx context.Context, h codec.Header, body []byte, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.Flags&codec.FlagUnencrypted != 0 {
		return errors.New("legacy write must not set unencrypted flag")
	}
	out := body
	if len(body) > 0 {
		key := c.secret.Bytes()
		out = codec.Obfuscate(h.SessionID, h.Version, h.SeqNo, key, body)
		wipe(key)
	}
	h.Length = uint32(len(out))
	pkt := append(h.Encode(), out...)
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

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var _ server.PacketIO = (*conn)(nil)

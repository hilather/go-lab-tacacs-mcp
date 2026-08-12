package server

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

// pipeIO is a clear PacketIO used by server unit tests (no obfuscation).
type pipeIO struct{ nc net.Conn }

func (p *pipeIO) RemoteAddr() net.Addr { return p.nc.RemoteAddr() }
func (p *pipeIO) Close() error         { return p.nc.Close() }

func (p *pipeIO) Read(ctx context.Context, maxBody uint32, deadline time.Time) (codec.Header, []byte, error) {
	if err := ctx.Err(); err != nil {
		return codec.Header{}, nil, err
	}
	_ = p.nc.SetReadDeadline(deadline)
	var raw [codec.HeaderSize]byte
	if _, err := io.ReadFull(p.nc, raw[:]); err != nil {
		return codec.Header{}, nil, err
	}
	h, err := codec.DecodeHeader(raw[:])
	if err != nil {
		return codec.Header{}, nil, err
	}
	body, err := h.AllocateBody(maxBody)
	if err != nil {
		return h, nil, err
	}
	if len(body) > 0 {
		if _, err := io.ReadFull(p.nc, body); err != nil {
			return h, nil, err
		}
	}
	return h, body, nil
}

func (p *pipeIO) Write(ctx context.Context, h codec.Header, body []byte, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.Length = uint32(len(body))
	pkt := append(h.Encode(), body...)
	_ = p.nc.SetWriteDeadline(deadline)
	_, err := p.nc.Write(pkt)
	return err
}

func testLimits() Limits {
	return Limits{
		MaxConnections:           32,
		MaxSessionsPerConnection: 16,
		MaxPacketBodyBytes:       codec.MaxBodyBytes,
		ReadTimeout:              2 * time.Second,
		WriteTimeout:             2 * time.Second,
		IdleTimeout:              2 * time.Second,
		HandshakeTimeout:         2 * time.Second,
		SingleConnectEnabled:     true,
		MaxLifetime:              time.Minute,
		ShutdownGrace:            time.Second,
	}
}

func testIdentity() Identity {
	return Identity{
		ClientID:  "lab",
		Transport: domain.TransportLegacy,
		Peer:      net.IPv4(127, 0, 0, 1),
		Revision:  1,
	}
}

func writePacket(nc net.Conn, h codec.Header, body []byte) error {
	h.Length = uint32(len(body))
	pkt := append(h.Encode(), body...)
	_ = nc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := nc.Write(pkt)
	return err
}

func readPacket(nc net.Conn) (codec.Header, []byte, error) {
	_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	var raw [codec.HeaderSize]byte
	if _, err := io.ReadFull(nc, raw[:]); err != nil {
		return codec.Header{}, nil, err
	}
	h, err := codec.DecodeHeader(raw[:])
	if err != nil {
		return codec.Header{}, nil, err
	}
	body, err := h.AllocateBody(codec.MaxBodyBytes)
	if err != nil {
		return h, nil, err
	}
	if len(body) > 0 {
		if _, err := io.ReadFull(nc, body); err != nil {
			return h, nil, err
		}
	}
	return h, body, nil
}

func authorBody(user string) []byte {
	b, err := codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		Service:      codec.AuthenServiceLogin,
		User:         []byte(user),
		Port:         []byte("tty0"),
		RemAddr:      []byte("127.0.0.1"),
	}.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func acctBody() []byte {
	b, err := codec.AcctRequest{
		Flags:        codec.AcctFlagStart,
		AuthenMethod: codec.AuthenMethodTACACS,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("alice"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("127.0.0.1"),
	}.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func authenStartBody() []byte {
	b, err := codec.AuthenStart{
		Action:  codec.AuthenActionLogin,
		Type:    codec.AuthenTypeASCII,
		Service: codec.AuthenServiceLogin,
		User:    []byte("alice"),
		Port:    []byte("tty0"),
		RemAddr: []byte("127.0.0.1"),
	}.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func startServe(lim Limits) (client net.Conn, done chan error) {
	return startServeH(lim, Stub{})
}

func startServeH(lim Limits, h Handler) (client net.Conn, done chan error) {
	a, b := net.Pipe()
	done = make(chan error, 1)
	go func() {
		done <- ServeConn(context.Background(), &pipeIO{nc: b}, testIdentity(), lim, h)
	}()
	return a, done
}

func continueBody() []byte {
	b, err := codec.AuthenContinue{}.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

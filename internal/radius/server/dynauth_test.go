package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestSignDynAuthRequestIndependentDecode(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	var auth [16]byte
	auth[0] = 1
	wire, err := SignDynAuthRequest(secret, codec.CodeCoARequest, 9, auth, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := testclient.DecodeDynAuthRequest(secret, wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Code != tcodec.CoARequest || pkt.Identifier != 9 {
		t.Fatalf("%+v", pkt)
	}
}

func TestOriginateCoAACKIndependentTestclient(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dest := ln.LocalAddr().String()
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			errc <- err
			return
		}
		pkt, err := testclient.DecodeDynAuthRequest(secret, buf[:n])
		if err != nil {
			errc <- err
			return
		}
		if pkt.Code != tcodec.CoARequest {
			errc <- errUnexpected("code", pkt.Code.String())
			return
		}
		if pkt.Attrs[0].Type != tcodec.TypeMessageAuthenticator {
			errc <- errUnexpected("ma-first", "")
			return
		}
		reply, err := testclient.EncodeDynAuthReply(secret, tcodec.CoAACK, pkt.Identifier, pkt.Authenticator, nil)
		if err != nil {
			errc <- err
			return
		}
		_, err = ln.WriteToUDP(reply, addr)
		errc <- err
	}()

	org := &Originator{Entropy: rand.Reader}
	res, err := org.Send(context.Background(), OriginateRequest{
		Secret:      secret,
		Destination: dest,
		Code:        codec.CodeCoARequest,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeAcctSessionID, Value: []byte("0001")},
		},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != DynAuthOutcomeACK {
		t.Fatalf("outcome=%+v", res)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestOriginateDisconnectNAKErrorCause(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt, err := testclient.DecodeDynAuthRequest(secret, buf[:n])
		if err != nil {
			return
		}
		var cause [4]byte
		binary.BigEndian.PutUint32(cause[:], 503)
		reply, err := testclient.EncodeDynAuthReply(secret, tcodec.DisconnectNAK, pkt.Identifier, pkt.Authenticator, []tcodec.Attr{
			{Type: tcodec.TypeErrorCause, Value: cause[:]},
		})
		if err != nil {
			return
		}
		_, _ = ln.WriteToUDP(reply, addr)
	}()
	org := &Originator{Entropy: rand.Reader}
	res, err := org.Send(context.Background(), OriginateRequest{
		Secret:      secret,
		Destination: ln.LocalAddr().String(),
		Code:        codec.CodeDisconnectRequest,
		Attributes:  attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("lab-admin")}},
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != DynAuthOutcomeNAK || res.ErrorCause != 503 {
		t.Fatalf("got %+v", res)
	}
}

func TestOriginateTimeout(t *testing.T) {
	t.Parallel()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	org := &Originator{Entropy: rand.Reader}
	res, err := org.Send(context.Background(), OriginateRequest{
		Secret:      []byte("LabSecret-16chars!"),
		Destination: ln.LocalAddr().String(),
		Code:        codec.CodeDisconnectRequest,
		Timeout:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != DynAuthOutcomeTimeout {
		t.Fatalf("got %+v", res)
	}
}

func TestOriginateCacheDoesNotCollapseCodes(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	var seen []codec.Code
	org := &Originator{
		Entropy: rand.Reader,
		Dial: func(_ context.Context, _, address string) (net.PacketConn, *net.UDPAddr, error) {
			addr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, nil, err
			}
			return &recordConn{onWrite: func(b []byte) {
				if len(b) > 0 {
					seen = append(seen, codec.Code(b[0]))
				}
			}}, addr, nil
		},
	}
	attrs := attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("lab-admin")}}
	id, dest := "h:same-handle", "127.0.0.1:9"
	for _, code := range []codec.Code{codec.CodeCoARequest, codec.CodeDisconnectRequest} {
		_, err := org.Send(context.Background(), OriginateRequest{
			Secret:      secret,
			Destination: dest,
			Code:        code,
			Attributes:  attrs,
			Timeout:     20 * time.Millisecond,
			CacheKey:    originateKeyForTest(id, dest, code, attrs),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0] != codec.CodeCoARequest || seen[1] != codec.CodeDisconnectRequest {
		t.Fatalf("datagrams=%v", seen)
	}
}

func originateKeyForTest(id, dest string, code codec.Code, attrs attribute.RawSet) string {
	// Must match operations.originateCacheKey: identity + dest + code + attrs.
	return string(rune(code)) + id + dest + string(rune(len(attrs)))
}

type recordConn struct {
	onWrite func([]byte)
}

func (c *recordConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, timeoutErr{}
}
func (c *recordConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.onWrite != nil {
		c.onWrite(p)
	}
	return len(p), nil
}
func (c *recordConn) Close() error                     { return nil }
func (c *recordConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestSignDynAuthRequestRequiresMAFirst(t *testing.T) {
	t.Parallel()
	var auth [16]byte
	wire, err := SignDynAuthRequest([]byte("LabSecret-16chars!"), codec.CodeCoARequest, 1, auth, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("u")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wire[codec.HeaderSize] != attribute.TypeMessageAuthenticator {
		t.Fatal("MA must be first")
	}
}

func TestSignDynAuthRejectsSessionTimeoutOnDisconnect(t *testing.T) {
	t.Parallel()
	var auth [16]byte
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 60)
	_, err := SignDynAuthRequest([]byte("LabSecret-16chars!"), codec.CodeDisconnectRequest, 1, auth, attribute.RawSet{
		{Type: attribute.TypeSessionTimeout, Value: buf[:]},
	})
	if err == nil {
		t.Fatal("expected illegal attr")
	}
}

type unexpectedError string

func errUnexpected(what, got string) error { return unexpectedError(what + ":" + got) }
func (e unexpectedError) Error() string    { return string(e) }

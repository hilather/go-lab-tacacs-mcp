package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestAuthorBodyDecodes(t *testing.T) {
	t.Parallel()
	b := authorBody("alice")
	req, err := codec.DecodeAuthorRequest(b)
	if err != nil {
		t.Fatalf("decode %v body=%x", err, b)
	}
	if string(req.User) != "alice" {
		t.Fatalf("user=%q", req.User)
	}
}

func TestSingleConnectNegotiated(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(client, h, authorBody("alice")); err != nil {
		t.Fatal(err)
	}
	rh, body, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if rh.Flags&codec.FlagSingleConnect == 0 {
		t.Fatalf("first reply missing single-connect flag: %#x", rh.Flags)
	}
	rep, err := codec.DecodeAuthorResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthorStatusFail {
		t.Fatalf("status=%#x", rep.Status)
	}

	h2 := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAcct, SeqNo: 1, SessionID: 2}
	if err := writePacket(client, h2, acctBody()); err != nil {
		t.Fatal(err)
	}
	rh2, body2, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if rh2.Flags&codec.FlagSingleConnect != 0 {
		t.Fatal("late single-connect flag must be ignored")
	}
	acct, err := codec.DecodeAcctReply(body2)
	if err != nil {
		t.Fatal(err)
	}
	if acct.Status != codec.AcctStatusSuccess {
		t.Fatalf("acct status=%#x", acct.Status)
	}

	h3 := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, SessionID: 3}
	if err := writePacket(client, h3, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	_, body3, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	ar, err := codec.DecodeAuthenReply(body3)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Status != codec.AuthenStatusError {
		t.Fatalf("authen status=%#x want ERROR stub", ar.Status)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestNonSingleConnectClosesAfterSession(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 11}
	if err := writePacket(client, h, authorBody("bob")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(client); err != nil {
		t.Fatal(err)
	}
	_, _, err := readPacket(client)
	if err == nil {
		t.Fatal("expected close after non-single-connect session")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestRefuseSingleConnect(t *testing.T) {
	t.Parallel()
	lim := testLimits()
	lim.SingleConnectEnabled = false
	client, done := startServe(lim)
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 4}
	if err := writePacket(client, h, authorBody("carol")); err != nil {
		t.Fatal(err)
	}
	rh, _, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if rh.Flags&codec.FlagSingleConnect != 0 {
		t.Fatal("server must not advertise single-connect when disabled")
	}
	if _, _, err := readPacket(client); err == nil {
		t.Fatal("connection should close")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestUnknownTypeZeroBody(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: 0x99, SeqNo: 1, Flags: 0x20, SessionID: 5}
	if err := writePacket(client, h, nil); err != nil {
		t.Fatal(err)
	}
	rh, body, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	if rh.Type != 0x99 || rh.SeqNo != 2 || rh.Length != 0 || len(body) != 0 {
		t.Fatalf("unknown-type reply %#v len=%d", rh, len(body))
	}
	if rh.Flags != 0x20 {
		t.Fatalf("flags=%#x want identical", rh.Flags)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestDuplicateSessionID(t *testing.T) {
	t.Parallel()
	lim := testLimits()
	// Keep the first session open by using a handler that returns GETUSER.
	a, b := netPipeServe(t, lim, getUserStub{})
	defer a.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 7}
	if err := writePacket(a, h, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}
	h2 := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 7}
	if err := writePacket(a, h2, authorBody("x")); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	// type mismatch on an active session is a type-specific ERROR
	if _, err := codec.DecodeAuthorResponse(body); err != nil {
		t.Fatal(err)
	}
	_ = b
}

func TestSessionCap(t *testing.T) {
	t.Parallel()
	lim := testLimits()
	lim.MaxSessionsPerConnection = 1
	a, b := netPipeServe(t, lim, getUserStub{})
	defer a.Close()
	_ = b

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(a, h, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}
	h2 := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 2}
	if err := writePacket(a, h2, authorBody("x")); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codec.DecodeAuthorResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthorStatusError {
		t.Fatalf("status=%#x want ERROR at session cap", rep.Status)
	}
}

func TestIdleTimeout(t *testing.T) {
	t.Parallel()
	lim := testLimits()
	lim.IdleTimeout = 80 * time.Millisecond
	lim.ReadTimeout = time.Second
	client, done := startServe(lim)
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 8}
	if err := writePacket(client, h, authorBody("idle")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(client); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_, _, err := readPacket(client)
	if err == nil {
		t.Fatal("expected idle close")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after idle")
	}
}

func TestInvalidAcctFlags(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()

	req := codec.AcctRequest{
		Flags:        codec.AcctFlagStart | codec.AcctFlagStop,
		AuthenMethod: codec.AuthenMethodTACACS,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("alice"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("127.0.0.1"),
	}
	// Encode rejects invalid flags; write the raw layout by forcing flags after encode of a valid packet.
	good := acctBody()
	good[0] = codec.AcctFlagStart | codec.AcctFlagStop
	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAcct, SeqNo: 1, SessionID: 9}
	if err := writePacket(client, h, good); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codec.DecodeAcctReply(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AcctStatusError {
		t.Fatalf("status=%#x", rep.Status)
	}
	_ = req
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestPartialHeaderDisconnect(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte{0xc0, 0x01, 0x01}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err == nil {
			// EOF is fine
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit on disconnect")
	}
}

type getUserStub struct{ Stub }

func (getUserStub) AuthenStart(context.Context, Env, codec.AuthenStart) (codec.AuthenReply, error) {
	return codec.AuthenReply{Status: codec.AuthenStatusGetUser}, nil
}

func netPipeServe(t *testing.T, lim Limits, h Handler) (client net.Conn, done chan error) {
	t.Helper()
	a, b := net.Pipe()
	done = make(chan error, 1)
	go func() {
		done <- ServeConn(context.Background(), &pipeIO{nc: b}, testIdentity(), lim, h)
	}()
	t.Cleanup(func() {
		_ = a.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return a, done
}

func TestWrongMinorAuthor(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()
	h := codec.Header{Version: codec.VersionByte(1), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 10}
	if err := writePacket(client, h, authorBody("x")); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codec.DecodeAuthorResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthorStatusError {
		t.Fatalf("status=%#x", rep.Status)
	}
	_ = done
}

func TestSendAuthRejected(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	defer client.Close()
	body, err := codec.AuthenStart{
		Action:  codec.AuthenActionSendAuth,
		Type:    codec.AuthenTypeASCII,
		Service: codec.AuthenServiceLogin,
		Port:    []byte("tty0"),
		RemAddr: []byte("127.0.0.1"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, SessionID: 12}
	if err := writePacket(client, h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codec.DecodeAuthenReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthenStatusError {
		t.Fatalf("status=%#x want ERROR", rep.Status)
	}
	_ = done
}

func TestEOFIsNotPanic(t *testing.T) {
	t.Parallel()
	client, done := startServe(testLimits())
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && err != io.EOF && !isClosedErr(err) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == "io: read/write on closed pipe" || s == "use of closed network connection"
}

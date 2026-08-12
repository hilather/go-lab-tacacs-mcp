package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestFlagErrorDrainsLiveSession(t *testing.T) {
	t.Parallel()
	a, done := netPipeServe(t, testLimits(), getUserStub{})
	defer a.Close()

	start := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(a, start, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}

	// seq 0 is a connection-level error: ERROR, drain, keep the live session.
	bad := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 0, SessionID: 99}
	if err := writePacket(a, bad, authorBody("x")); err != nil {
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
		t.Fatalf("status=%#x", rep.Status)
	}

	// New session must be refused while draining.
	neu := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 2}
	if err := writePacket(a, neu, authorBody("y")); err != nil {
		t.Fatal(err)
	}
	_, body, err = readPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	rep, err = codec.DecodeAuthorResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthorStatusError {
		t.Fatalf("new session status=%#x want ERROR", rep.Status)
	}

	// Live GETUSER session still accepts CONTINUE.
	cont := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 3, SessionID: 1}
	if err := writePacket(a, cont, continueBody()); err != nil {
		t.Fatal(err)
	}
	_, body, err = readPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	ar, err := codec.DecodeAuthenReply(body)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Status != codec.AuthenStatusError {
		t.Fatalf("continue status=%#x", ar.Status)
	}
	_ = done
}

func TestBadMajorDrainsLiveSession(t *testing.T) {
	t.Parallel()
	a, _ := netPipeServe(t, testLimits(), getUserStub{})
	defer a.Close()

	start := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(a, start, authenStartBody()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}

	bad := codec.Header{Version: 0xb0, Type: codec.TypeAuthor, SeqNo: 1, SessionID: 3}
	if err := writePacket(a, bad, authorBody("z")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}

	cont := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 3, SessionID: 1}
	if err := writePacket(a, cont, continueBody()); err != nil {
		t.Fatal(err)
	}
	_, body, err := readPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.DecodeAuthenReply(body); err != nil {
		t.Fatal(err)
	}
}

func TestSecondSessionNotDispatchedBeforeFirstReply(t *testing.T) {
	t.Parallel()
	g := &gateAuthor{entered: make(chan struct{}), release: make(chan struct{})}
	a, _ := netPipeServe(t, testLimits(), g)
	defer a.Close()

	first := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(a, first, authorBody("one")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first handler not entered")
	}
	if n := g.calls.Load(); n != 1 {
		t.Fatalf("calls=%d want 1", n)
	}

	wrote := make(chan error, 1)
	go func() {
		second := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, SessionID: 2}
		wrote <- writePacket(a, second, authorBody("two"))
	}()
	time.Sleep(50 * time.Millisecond)
	if n := g.calls.Load(); n != 1 {
		t.Fatalf("second session dispatched early: calls=%d", n)
	}
	close(g.release)
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second write blocked")
	}
	if _, _, err := readPacket(a); err != nil {
		t.Fatal(err)
	}
	if n := g.calls.Load(); n != 2 {
		t.Fatalf("calls=%d want 2", n)
	}
}

func TestMaxLifetimeClosesConnection(t *testing.T) {
	t.Parallel()
	lim := testLimits()
	lim.MaxLifetime = 80 * time.Millisecond
	lim.IdleTimeout = time.Second
	lim.ReadTimeout = time.Second
	client, done := startServe(lim)
	defer client.Close()

	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 1}
	if err := writePacket(client, h, authorBody("life")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPacket(client); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, _, err := readPacket(client); err == nil {
		t.Fatal("expected max-lifetime close")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

type gateAuthor struct {
	Stub
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (g *gateAuthor) Authorize(ctx context.Context, env Env, req codec.AuthorRequest) (codec.AuthorResponse, error) {
	n := g.calls.Add(1)
	if n == 1 {
		close(g.entered)
		select {
		case <-g.release:
		case <-ctx.Done():
			return codec.AuthorResponse{Status: codec.AuthorStatusError}, ctx.Err()
		}
	}
	return codec.AuthorResponse{Status: codec.AuthorStatusFail}, nil
}

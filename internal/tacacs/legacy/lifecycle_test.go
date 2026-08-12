package legacy

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

type getUser struct{ server.Stub }

func (getUser) AuthenStart(context.Context, server.Env, codec.AuthenStart) (codec.AuthenReply, error) {
	return codec.AuthenReply{Status: codec.AuthenStatusGetUser}, nil
}

type holdStart struct {
	server.Stub
	started chan struct{}
	release chan struct{}
}

func (h *holdStart) AuthenStart(ctx context.Context, _ server.Env, _ codec.AuthenStart) (codec.AuthenReply, error) {
	select {
	case <-h.started:
	default:
		close(h.started)
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return codec.AuthenReply{Status: codec.AuthenStatusError}, ctx.Err()
	}
	return codec.AuthenReply{Status: codec.AuthenStatusGetUser}, nil
}

type holdContinue struct {
	server.Stub
	entered chan struct{}
	release chan struct{}
}

func (h *holdContinue) AuthenStart(context.Context, server.Env, codec.AuthenStart) (codec.AuthenReply, error) {
	return codec.AuthenReply{Status: codec.AuthenStatusGetUser}, nil
}

func (h *holdContinue) AuthenContinue(ctx context.Context, _ server.Env, _ codec.AuthenContinue) (codec.AuthenReply, error) {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return codec.AuthenReply{Status: codec.AuthenStatusError}, ctx.Err()
	}
	return codec.AuthenReply{Status: codec.AuthenStatusError}, nil
}

func TestServeCancelDoesNotAbortInFlight(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	h := &holdStart{started: make(chan struct{}), release: make(chan struct{})}
	doc, err := config.Parse([]byte(testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`)))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(Options{
		Bind: doc.Listeners.LegacyTACACS.Bind, Settings: doc.Listeners.LegacyTACACS,
		Grace: time.Second, Snapshot: mgr.Snapshot, Secrets: lookup, Handler: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopAccept := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(serveCtx) }()
	defer func() {
		stopAccept()
		shut, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = ln.Shutdown(shut)
		<-errc
	}()
	waitReady(t, ln)

	cli, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	body, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}
	if err := cli.WritePacket(hdr, body); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not started")
	}
	stopAccept()
	time.Sleep(20 * time.Millisecond)
	close(h.release)
	_, rbody, err := cli.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.StatusGetUser {
		t.Fatalf("status=%#x want GETUSER after accept-loop cancel", rep.Status)
	}
}

func TestUnencryptedDrainsLiveSession(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListenerH(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil, getUser{})

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	startBody, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, startBody); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}

	author, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("x"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagUnencrypted, SessionID: 9}, author); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorError {
		t.Fatalf("unencrypted status=%#x", arep.Status)
	}

	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 10}, author); err != nil {
		t.Fatal(err)
	}
	_, rbody, err = c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	arep, err = tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if arep.Status != tcodec.AuthorError {
		t.Fatalf("new session status=%#x want ERROR", arep.Status)
	}

	cont, err := tcodec.WriteCont(tcodec.Cont{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, SessionID: 1}, cont); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
}

func TestInboxFullDoesNotStarveSibling(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	h := &holdContinue{entered: make(chan struct{}), release: make(chan struct{})}
	ln, _ := startListenerH(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil, h)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	startBody, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, startBody); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	cont, err := tcodec.WriteCont(tcodec.Cont{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, SessionID: 1}, cont); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("continue not entered")
	}
	// Fill inbox, then one more that would block a blocking offer.
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 5, SessionID: 1}, cont); err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 7, SessionID: 1}, cont); err != nil {
		t.Fatal(err)
	}
	author, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("sib"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 2}, author); err != nil {
		t.Fatal(err)
	}

	gotAuthor := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !gotAuthor {
		c.SetDeadlines(200 * time.Millisecond)
		rh, rbody, err := c.ReadPacket()
		if err != nil {
			continue
		}
		if rh.Type == tcodec.TypeAuthor {
			rep, err := tcodec.ReadAuthorRep(rbody)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Status != tcodec.AuthorFail {
				t.Fatalf("sibling status=%#x", rep.Status)
			}
			gotAuthor = true
		}
	}
	if !gotAuthor {
		t.Fatal("sibling author starved by full inbox")
	}
	close(h.release)
}

func TestConnectionCapClosesWithNoPacket(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	yaml := fmt.Sprintf(`
schema_version: 1
listeners:
  legacy_tacacs:
    enabled: true
    bind: "127.0.0.1:0"
    max_connections: 1
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: loop
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
`, sec)
	ln, _ := startListenerH(t, yaml, nil, getUser{})

	hold, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	startBody, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hold.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, startBody); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hold.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	if n := ln.Engine().Active(); n > 1 {
		t.Fatalf("active=%d", n)
	}

	extra, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetDeadlines(500 * time.Millisecond)
	_, _, err = extra.ReadPacket()
	if err == nil {
		t.Fatal("over-cap connection should close with no packet")
	}
	if n := ln.Engine().Active(); n > 1 {
		t.Fatalf("active=%d after reject", n)
	}
}

func TestBindForLifeAcrossReload(t *testing.T) {
	dir := t.TempDir()
	secA := writeSecret(t, dir, "a", testSecret)
	secB := writeSecret(t, dir, "b", "OtherSecret-16ch!")
	ln, mgr := startListener(t, testYAML(secA, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	author, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 1}, author); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadPacket(); err != nil {
		t.Fatal(err)
	}

	_, err = mgr.UpdateClient("loop", state.UpdateClient{
		SharedSecret: &state.SecretPatch{Ref: config.SecretRef{
			Purpose: credentials.PurposeLegacySharedSecret,
			File:    secB,
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 2}, author); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadAuthorRep(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorFail {
		t.Fatalf("old secret after reload status=%#x", rep.Status)
	}
}

func TestWrongSecretAllFamilies(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	ln, _ := startListener(t, testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`), nil)

	cases := []struct {
		name string
		typ  byte
		body []byte
	}{
		{"authen", tcodec.TypeAuthen, mustStart()},
		{"author", tcodec.TypeAuthor, mustAuthor()},
		{"acct", tcodec.TypeAcct, mustAcct()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			w := tclient.New(nc, []byte("WrongSecret-16ch!"))
			r := tclient.New(nc, []byte(testSecret))
			h := tcodec.Header{Version: tcodec.VersionByte(0), Type: tc.typ, SeqNo: 1, SessionID: 1}
			if tc.typ == tcodec.TypeAuthen {
				h.Version = tcodec.VersionByte(0)
			}
			if err := w.WritePacket(h, tc.body); err != nil {
				t.Fatal(err)
			}
			rh, rbody, err := r.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			switch tc.typ {
			case tcodec.TypeAuthen:
				rep, err := tcodec.ReadReply(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.StatusError {
					t.Fatalf("status=%#x", rep.Status)
				}
			case tcodec.TypeAuthor:
				rep, err := tcodec.ReadAuthorRep(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.AuthorError {
					t.Fatalf("status=%#x", rep.Status)
				}
			case tcodec.TypeAcct:
				rep, err := tcodec.ReadAcctRep(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.AcctErr {
					t.Fatalf("status=%#x", rep.Status)
				}
			}
			_ = rh
		})
	}
}

func TestCrossSecretIPv4IPv6(t *testing.T) {
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	_ = ln6.Close()

	dir := t.TempDir()
	secA := writeSecret(t, dir, "a", testSecret)
	secB := writeSecret(t, dir, "b", "OtherSecret-16ch!")
	yaml := fmt.Sprintf(`
schema_version: 1
listeners:
  legacy_tacacs:
    enabled: true
    bind: "127.0.0.1:0"
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: v4
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
  - id: v6
    priority: 10
    match: {source_cidrs: ["::1/128"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
`, secA, secB)
	ln4, _ := startListener(t, yaml, nil)
	yaml6 := fmt.Sprintf(`
schema_version: 1
listeners:
  legacy_tacacs:
    enabled: true
    bind: "[::1]:0"
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: v4
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
  - id: v6
    priority: 10
    match: {source_cidrs: ["::1/128"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
`, secA, secB)
	ln6b, _ := startListener(t, yaml6, nil)

	// v4 peer with v6 secret must ERROR.
	requireFamilyError(t, ln4.Addr().String(), []byte("OtherSecret-16ch!"), []byte(testSecret))
	// v6 peer with v4 secret must ERROR.
	requireFamilyError(t, ln6b.Addr().String(), []byte(testSecret), []byte("OtherSecret-16ch!"))
	// matching secrets succeed.
	c, err := tclient.Dial(ln4.Addr().String(), []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}, mustAuthor()); err != nil {
		t.Fatal(err)
	}
	_, body, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadAuthorRep(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorFail {
		t.Fatalf("matched v4 status=%#x", rep.Status)
	}
}

func TestSlowlorisHandshakeTimeout(t *testing.T) {
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	yaml := fmt.Sprintf(`
schema_version: 1
listeners:
  legacy_tacacs:
    enabled: true
    bind: "127.0.0.1:0"
    handshake_timeout: 80ms
    read_timeout: 2s
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 2s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
clients:
  - id: loop
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: %q}}
`, sec)
	ln, _ := startListener(t, yaml, nil)
	nc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte{0xc0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_ = nc.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := nc.Write([]byte{0x01}); err == nil {
		buf := make([]byte, 8)
		_, rerr := nc.Read(buf)
		if rerr == nil {
			t.Fatal("slowloris connection stayed open")
		}
	}
}

func TestStartStopNoLeak(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()
	dir := t.TempDir()
	sec := writeSecret(t, dir, "secret", testSecret)
	for i := 0; i < 8; i++ {
		doc, err := config.Parse([]byte(testYAML(sec, "127.0.0.1:0", `"127.0.0.0/8"`)))
		if err != nil {
			t.Fatal(err)
		}
		lookup := func(ref config.SecretRef) ([]byte, error) { return os.ReadFile(ref.File) }
		mgr, err := state.New(doc, state.Options{Secrets: lookup})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := Listen(Options{
			Bind: doc.Listeners.LegacyTACACS.Bind, Settings: doc.Listeners.LegacyTACACS,
			Grace: time.Second, Snapshot: mgr.Snapshot, Secrets: lookup, Handler: server.Stub{},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- ln.Serve(ctx) }()
		waitReady(t, ln)
		c, err := tclient.Dial(ln.Addr().String(), []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}, mustAuthor()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.ReadPacket(); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		cancel()
		shut, done := context.WithTimeout(context.Background(), time.Second)
		_ = ln.Shutdown(shut)
		done()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
			t.Fatal("serve stuck")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		runtime.GC()
		n = runtime.NumGoroutine()
		if n <= base+8 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: have %d baseline %d", n, base)
}

func waitReady(t *testing.T, ln *Listener) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !ln.Ready() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !ln.Ready() {
		t.Fatal("listener not ready")
	}
}

func requireFamilyError(t *testing.T, addr string, writeKey, readKey []byte) {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	w := tclient.New(nc, writeKey)
	r := tclient.New(nc, readKey)
	if err := w.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthor, SeqNo: 1, SessionID: 1}, mustAuthor()); err != nil {
		t.Fatal(err)
	}
	_, body, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadAuthorRep(body)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != tcodec.AuthorError {
		t.Fatalf("cross-secret status=%#x", rep.Status)
	}
}

func mustStart() []byte {
	b, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		panic(err)
	}
	return b
}

func mustAuthor() []byte {
	b, err := tcodec.WriteAuthorReq(tcodec.AuthorReq{
		Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		panic(err)
	}
	return b
}

func mustAcct() []byte {
	b, err := tcodec.WriteAcctReq(tcodec.AcctReq{
		Flags: tcodec.AcctStart, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
		User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
	})
	if err != nil {
		panic(err)
	}
	return b
}

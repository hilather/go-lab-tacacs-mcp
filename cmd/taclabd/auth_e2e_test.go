package main

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	tclient "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestRemainingAuthFlowsE2E(t *testing.T) {
	dir := t.TempDir()
	phc, err := credentials.DeriveArgon2id([]byte(e2ePassword), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	en, err := credentials.DeriveArgon2id([]byte("enablepass1!"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	enable := filepath.Join(dir, "enable")
	chal := filepath.Join(dir, "chal")
	sec := filepath.Join(dir, "shared")
	tok := filepath.Join(dir, "token")
	chalSecret := []byte("chap-secret-16ch!")
	for _, f := range []struct {
		path string
		data []byte
	}{
		{login, phc},
		{enable, en},
		{chal, chalSecret},
		{sec, []byte(e2eSecret)},
		{tok, []byte(e2eToken)},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `
schema_version: 1
server:
  shutdown_grace: 2s
listeners:
  legacy_tacacs:
    enabled: true
    bind: 127.0.0.1:0
    single_connect: {enabled: true, max_lifetime: 1m, idle_timeout: 5s}
  secure_tacacs: {enabled: false}
  http: {enabled: false}
observability:
  metrics: {enabled: false}
clients:
  - id: lab-switches
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
    authentication: {allowed_methods: [ascii, pap, chap, enable]}
users:
  - id: lab-admin
    credentials:
      login: {verifier: {file: ` + login + `}}
      challenge: {secret: {file: ` + chal + `}}
      enable: {verifier: {file: ` + enable + `}}
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuf
	errc := make(chan int, 1)
	go func() { errc <- serve(ctx, []string{"--config", cfg}, &stdout, &stderr) }()
	legacyAddr := waitServeAddr(t, &stdout, &stderr)

	c, err := tclient.Dial(legacyAddr, []byte(e2eSecret))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	pap, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypePAP, Service: tcodec.SvcLogin,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Data: []byte(e2ePassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(1), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 11}, pap); err != nil {
		t.Fatal(err)
	}
	if status := readAuthenStatus(t, c); status != tcodec.StatusPass {
		t.Fatalf("pap=%#x stderr=%s", status, stderr.String())
	}

	id := byte(0x42)
	chal8 := []byte("12345678")
	resp := credentials.CHAPResponse(id, chalSecret, chal8)
	chapData, err := tcodec.PackChap(tcodec.Chap{ID: id, Chal: chal8, Resp: resp})
	if err != nil {
		t.Fatal(err)
	}
	chap, err := tcodec.WriteStart(tcodec.Start{
		Action: tcodec.ActionLogin, AType: tcodec.TypeCHAP, Service: tcodec.SvcPPP,
		User: []byte("lab-admin"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
		Data: chapData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(1), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: 12}, chap); err != nil {
		t.Fatal(err)
	}
	if status := readAuthenStatus(t, c); status != tcodec.StatusPass {
		t.Fatalf("chap=%#x", status)
	}

	for i, typ := range []byte{tcodec.TypeASCII, tcodec.TypePAP} {
		enBody, err := tcodec.WriteStart(tcodec.Start{
			Action: tcodec.ActionLogin, AType: typ, Service: tcodec.SvcEnable, Priv: 15,
			User: []byte("lab-admin"), Port: []byte("con"), RemAddr: []byte("127.0.0.1"),
		})
		if err != nil {
			t.Fatal(err)
		}
		sid := uint32(20 + i)
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 1, Flags: tcodec.FlagSingleConnect, SessionID: sid}, enBody); err != nil {
			t.Fatal(err)
		}
		if status := readAuthenStatus(t, c); status != tcodec.StatusGetPass {
			t.Fatalf("enable type=%#x start=%#x", typ, status)
		}
		cbody, err := tcodec.WriteCont(tcodec.Cont{Msg: []byte("enablepass1!")})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WritePacket(tcodec.Header{Version: tcodec.VersionByte(0), Type: tcodec.TypeAuthen, SeqNo: 3, Flags: tcodec.FlagSingleConnect, SessionID: sid}, cbody); err != nil {
			t.Fatal(err)
		}
		if status := readAuthenStatus(t, c); status != tcodec.StatusPass {
			t.Fatalf("enable type=%#x pass=%#x", typ, status)
		}
	}

	cancel()
	select {
	case code := <-errc:
		if code != 0 {
			t.Fatalf("exit %d stderr=%s", code, stderr.String())
		}
	case <-time.After(4 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func readAuthenStatus(t *testing.T, c *tclient.Conn) byte {
	t.Helper()
	_, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tcodec.ReadReply(rbody)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Status
}

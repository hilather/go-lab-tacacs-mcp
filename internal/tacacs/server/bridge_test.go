package server

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestStartCloseDropsAAASession(t *testing.T) {
	t.Parallel()
	svc := testAAA(t)
	client, done := startServeH(testLimits(), Bridge{AAA: svc})
	body, err := codec.AuthenStart{
		Action:  codec.AuthenActionLogin,
		Type:    codec.AuthenTypeASCII,
		Service: codec.AuthenServiceLogin,
		User:    []byte("lab-admin"),
		Port:    []byte("tty0"),
		RemAddr: []byte("127.0.0.1"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthen, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 42}
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
	if rep.Status != codec.AuthenStatusGetPass {
		t.Fatalf("status=%#x", rep.Status)
	}
	if svc.InFlight() != 1 {
		t.Fatalf("inflight=%d", svc.InFlight())
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit after close")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if svc.InFlight() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("aaa session leaked: inflight=%d", svc.InFlight())
}

func TestBridgeAuthenMethodNotType(t *testing.T) {
	t.Parallel()
	svc := testAAA(t)
	dec, err := Bridge{AAA: svc}.Authorize(t.Context(), Env{Identity: Identity{ClientID: "lab"}}, codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		AuthenType:   codec.AuthenTypeASCII,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("127.0.0.1"),
		Args:         []codec.Argument{{Name: "service", Separator: '=', Value: "shell"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Status != codec.AuthorStatusPassAdd {
		t.Fatalf("status=%#x", dec.Status)
	}
	// Bridge no longer copies authen_type into the method field. Inspect via AAA.
	got, err := svc.ExplainAuthorization(t.Context(), aaa.AuthorizationRequest{
		UserID:       "lab-admin",
		ClientID:     "lab",
		Service:      "shell",
		AuthenMethod: domain.AuthenMethod(codec.AuthenMethodTACACS),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthenMethod == "ascii" {
		t.Fatalf("method TACACS / type ASCII must not trace as ascii: %+v", got)
	}
	if got.AuthenMethod != "tacacs" {
		t.Fatalf("method=%q", got.AuthenMethod)
	}
}

func testAAA(t *testing.T) *aaa.Service {
	t.Helper()
	dir := t.TempDir()
	phc, err := credentials.DeriveArgon2id([]byte("labpass1!"), credentials.TestParams, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login := filepath.Join(dir, "login")
	sec := filepath.Join(dir, "shared")
	if err := os.WriteFile(login, phc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte("LabSecret-16chars!"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `
schema_version: 1
listeners:
  secure_tacacs: {enabled: false}
clients:
  - id: lab
    priority: 10
    match: {source_cidrs: ["127.0.0.0/8"], transports: [legacy]}
    legacy: {shared_secret: {file: ` + sec + `}}
    authentication: {allowed_methods: [ascii]}
groups:
  - id: administrators
    priority: 10
    services:
      - service: shell
        action: permit
        reply_attributes:
          - {name: priv-lvl, separator: "=", value: "15"}
    command_rules:
      - id: permit-configure
        priority: 10
        action: permit
        command: {exact: configure}
        arguments: {pattern: ".*"}
users:
  - id: lab-admin
    group_ids: [administrators]
    credentials:
      login: {verifier: {file: ` + login + `}}
`
	doc, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(ref config.SecretRef) ([]byte, error) {
		b, err := os.ReadFile(ref.File)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	}
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := aaa.New(aaa.Options{
		Manager: mgr,
		Secrets: lookup,
		Creds:   credentials.Options{Params: credentials.TestParams},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

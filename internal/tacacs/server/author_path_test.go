package server

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

func TestLiveAuthorPacketsTwoEvaluators(t *testing.T) {
	t.Parallel()
	svc := testAAA(t)
	b := Bridge{AAA: svc}
	env := Env{Identity: Identity{ClientID: "lab", Transport: domain.TransportLegacy}}

	session, err := b.Authorize(t.Context(), env, codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		PrivLvl:      1,
		AuthenType:   codec.AuthenTypeASCII,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("192.0.2.10"),
		Args: []codec.Argument{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: ""},
			{Name: "priv-lvl", Separator: '=', Value: "1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != codec.AuthorStatusPassAdd {
		t.Fatalf("session status=%#x", session.Status)
	}
	if !argsEqual(session.Args, []codec.Argument{{Name: "priv-lvl", Separator: '=', Value: "15"}}) {
		t.Fatalf("session args=%+v", session.Args)
	}

	cmd, err := b.Authorize(t.Context(), env, codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		AuthenType:   codec.AuthenTypeASCII,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("192.0.2.10"),
		Args: []codec.Argument{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: "configure"},
			{Name: "cmd-arg", Separator: '=', Value: "terminal"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != codec.AuthorStatusPassAdd {
		t.Fatalf("configure status=%#x", cmd.Status)
	}
	if len(cmd.Args) != 0 {
		t.Fatalf("PASS_ADD zero args, got %+v", cmd.Args)
	}

	deny, err := b.Authorize(t.Context(), env, codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("192.0.2.10"),
		Args: []codec.Argument{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: "reload"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if deny.Status != codec.AuthorStatusFail {
		t.Fatalf("reload status=%#x", deny.Status)
	}
}

func TestLiveAuthorServicePermitNeverAuthorizesCommand(t *testing.T) {
	t.Parallel()
	svc := testAAA(t)
	b := Bridge{AAA: svc}
	env := Env{Identity: Identity{ClientID: "lab"}}
	// testAAA administrators have a shell service permit and only configure as a command.
	// A non-empty cmd that is not configure must FAIL, not inherit the shell permit.
	got, err := b.Authorize(t.Context(), env, codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodLocal,
		AuthenType:   codec.AuthenTypePAP,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("con0"),
		RemAddr:      []byte("2001:db8::1"),
		Args: []codec.Argument{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: "write"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != codec.AuthorStatusFail {
		t.Fatalf("write must not inherit shell permit, status=%#x", got.Status)
	}
}

func TestLiveAuthorWireRoundTrip(t *testing.T) {
	t.Parallel()
	svc := testAAA(t)
	client, done := startServeH(testLimits(), Bridge{AAA: svc})
	t.Cleanup(func() {
		_ = client.Close()
		<-done
	})

	body, err := codec.AuthorRequest{
		AuthenMethod: codec.AuthenMethodTACACS,
		PrivLvl:      15,
		AuthenType:   codec.AuthenTypeASCII,
		Service:      codec.AuthenServiceLogin,
		User:         []byte("lab-admin"),
		Port:         []byte("tty0"),
		RemAddr:      []byte("127.0.0.1"),
		Args: []codec.Argument{
			{Name: "service", Separator: '=', Value: "shell"},
			{Name: "cmd", Separator: '=', Value: ""},
			{Name: "inacl", Separator: '*', Value: "std"},
			{Name: "vendor-x", Separator: '=', Value: "keep=eq*star"},
		},
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	h := codec.Header{Version: codec.VersionByte(0), Type: codec.TypeAuthor, SeqNo: 1, Flags: codec.FlagSingleConnect, SessionID: 9}
	if err := writePacket(client, h, body); err != nil {
		t.Fatal(err)
	}
	_, rbody, err := readPacket(client)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codec.DecodeAuthorResponse(rbody)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != codec.AuthorStatusPassAdd {
		t.Fatalf("wire status=%#x", rep.Status)
	}
	if !argsEqual(rep.Args, []codec.Argument{{Name: "priv-lvl", Separator: '=', Value: "15"}}) {
		t.Fatalf("wire args=%+v", rep.Args)
	}
	if rep.Status == codec.AuthorStatusFollow {
		t.Fatal("FOLLOW must not be emitted")
	}
}

func argsEqual(got, want []codec.Argument) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

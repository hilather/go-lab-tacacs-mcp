package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

var testSecret = []byte("LabRadius-Secret-32-bytes-ok!!")

func TestSignResponseMAFirstThenResponseAuthenticator(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(i + 1)
	}
	proxy := attribute.RawSet{{Type: attribute.TypeProxyState, Value: []byte("ps")}}
	wire, err := SignResponse(testSecret, codec.CodeAccessReject, 7, ra, proxy)
	if err != nil {
		t.Fatal(err)
	}
	assertSigned(t, wire, codec.CodeAccessReject, 7, ra, testSecret)
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attributes.Len() < 2 || pkt.Attributes[0].Type != attribute.TypeMessageAuthenticator {
		t.Fatalf("MA must be first: %+v", pkt.Attributes)
	}
	if pkt.Attributes[1].Type != attribute.TypeProxyState || !bytes.Equal(pkt.Attributes[1].Value, []byte("ps")) {
		t.Fatalf("Proxy-State: %+v", pkt.Attributes)
	}
}

func TestStubAccessRejectsAfterDecode(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0xab
	req := codec.Packet{Code: codec.CodeAccessRequest, Identifier: 3, Authenticator: ra}
	declared, err := codec.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	res := Stub{}.Handle(context.Background(), Request{
		Role:     domain.RoleAccess,
		Packet:   req,
		Declared: declared,
		Secret:   testSecret,
	})
	if res.Action != ActionReply || res.Reason != ReasonUnsupportedMethod {
		t.Fatalf("got %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 3, ra, testSecret)
}

func TestStubAccountingResponseValidatesRequestAuthenticator(t *testing.T) {
	t.Parallel()
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: 4}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(testSecret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	declared, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	res := Stub{}.Handle(context.Background(), Request{
		Role:     domain.RoleAccounting,
		Packet:   pkt,
		Declared: declared,
		Secret:   testSecret,
	})
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("got %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccountingResponse, 4, auth, testSecret)

	bad := pkt
	bad.Authenticator[0] ^= 0xff
	badDecl, err := codec.Encode(bad)
	if err != nil {
		t.Fatal(err)
	}
	res = Stub{}.Handle(context.Background(), Request{
		Role:     domain.RoleAccounting,
		Packet:   bad,
		Declared: badDecl,
		Secret:   testSecret,
	})
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidAcctAuth {
		t.Fatalf("invalid acct auth: %+v", res)
	}
}

func TestStubDiscardsWrongCode(t *testing.T) {
	t.Parallel()
	res := Stub{}.Handle(context.Background(), Request{
		Role:   domain.RoleAccess,
		Packet: codec.Packet{Code: codec.CodeAccessAccept},
		Secret: testSecret,
	})
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidCode {
		t.Fatalf("got %+v", res)
	}
}

func assertSigned(t *testing.T, wire []byte, code codec.Code, id uint8, reqAuth [16]byte, secret []byte) {
	t.Helper()
	if err := crypto.ValidateResponseAuthenticator(secret, wire, reqAuth); err != nil {
		t.Fatalf("response authenticator: %v", err)
	}
	work := append([]byte(nil), wire...)
	copy(work[4:20], reqAuth[:])
	if err := crypto.ValidateMessageAuthenticator(secret, work); err != nil {
		t.Fatalf("message authenticator: %v", err)
	}
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Code != code || pkt.Identifier != id {
		t.Fatalf("code=%s id=%d", pkt.Code, pkt.Identifier)
	}
	if pkt.Attributes.Len() == 0 || pkt.Attributes[0].Type != attribute.TypeMessageAuthenticator {
		t.Fatal("Message-Authenticator must be first")
	}
}

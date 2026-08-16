package testclient

import (
	"bytes"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestEAPIdentityMD5PacketsIndependent(t *testing.T) {
	t.Parallel()
	ident := EAPIdentityResponse(1, "lab-admin")
	raw := EncodeEAP(ident)
	got, err := DecodeEAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != EAPCodeResponse || got.Type != EAPTypeIdentity || string(got.Data) != "lab-admin" {
		t.Fatalf("%+v", got)
	}

	chal := bytes.Repeat([]byte{0x22}, 16)
	hash := MD5Response(2, []byte("chap-secret-16ch!"), chal)
	resp := EAPMD5Response(2, hash)
	got, err = DecodeEAP(EncodeEAP(resp))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != EAPTypeMD5 || len(got.Data) != 17 || got.Data[0] != 16 {
		t.Fatalf("%+v", got)
	}

	req := EAPPacket{Code: EAPCodeRequest, Identifier: 2, Type: EAPTypeMD5, HasType: true, Data: append([]byte{16}, chal...)}
	extracted, err := ParseMD5Challenge(req)
	if err != nil || !bytes.Equal(extracted, chal) {
		t.Fatalf("chal=%x err=%v", extracted, err)
	}

	fail := EncodeEAP(EAPPacket{Code: EAPCodeFailure, Identifier: 2})
	if len(fail) != 4 || fail[0] != EAPCodeFailure {
		t.Fatalf("failure=%x", fail)
	}
	ok := EncodeEAP(EAPPacket{Code: EAPCodeSuccess, Identifier: 2})
	if len(ok) != 4 || ok[0] != EAPCodeSuccess {
		t.Fatalf("success=%x", ok)
	}
}

func TestConcatEAPMessage(t *testing.T) {
	t.Parallel()
	first := EncodeEAP(EAPIdentityResponse(1, "ab"))
	if len(first) < 6 {
		t.Fatal(first)
	}
	attrs := []codec.Attr{
		{Type: codec.TypeEAPMessage, Value: first[:4]},
		{Type: codec.TypeEAPMessage, Value: first[4:]},
	}
	got := ConcatEAPMessage(attrs)
	if !bytes.Equal(got, first) {
		t.Fatalf("%x != %x", got, first)
	}
	pkt, err := FirstEAP(attrs)
	if err != nil || string(pkt.Data) != "ab" {
		t.Fatalf("%+v %v", pkt, err)
	}
}

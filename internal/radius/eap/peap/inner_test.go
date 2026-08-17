package peap

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeMSCHAPChallengeResponse(t *testing.T) {
	t.Parallel()
	chal := bytes.Repeat([]byte{0x11}, 16)
	raw := EncodeMSCHAPChallenge(3, 7, chal, "taclab")
	p, err := DecodeInner(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Code != innerCodeRequest || p.Type != InnerMSCHAPv2 || p.Identifier != 3 {
		t.Fatalf("%+v", p)
	}
	if p.Data[0] != MSCHAPOpChallenge || p.Data[1] != 7 || p.Data[4] != 16 {
		t.Fatalf("hdr=%x", p.Data[:5])
	}
	if !bytes.Equal(p.Data[5:21], chal) || string(p.Data[21:]) != "taclab" {
		t.Fatalf("body=%x", p.Data)
	}

	resp := make([]byte, 49)
	copy(resp[0:16], bytes.Repeat([]byte{0x22}, 16))
	copy(resp[24:48], bytes.Repeat([]byte{0x33}, 24))
	inner := EncodeInner(InnerPacket{
		Code: innerCodeResponse, Identifier: 3, Type: InnerMSCHAPv2, HasType: true,
		Data: append(append([]byte{MSCHAPOpResponse, 7, 0, 54, 49}, resp...), []byte("lab-admin")...),
	})
	got, err := DecodeInner(inner)
	if err != nil {
		t.Fatal(err)
	}
	msID, response, name, ok := ParseMSCHAPResponse(got)
	if !ok || msID != 7 || name != "lab-admin" || !bytes.Equal(response, resp) {
		t.Fatalf("msID=%d name=%q resp=%x ok=%v", msID, name, response, ok)
	}
}

func TestEncodeFlightFragments(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte{0x16}, MaxTLSPerMessage+20)
	parts := EncodeFlight(big)
	if len(parts) < 2 {
		t.Fatalf("parts=%d", len(parts))
	}
	first, err := Parse(parts[0])
	if err != nil || !first.LengthIncluded || !first.MoreFragments || first.TLSMessageLen != uint32(len(big)) {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	last, err := Parse(parts[len(parts)-1])
	if err != nil || last.MoreFragments {
		t.Fatalf("last=%+v err=%v", last, err)
	}
}

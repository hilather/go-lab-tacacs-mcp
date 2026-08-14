package codec

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

func TestDecodeHeaderTruncation(t *testing.T) {
	t.Parallel()
	raw := make([]byte, HeaderSize)
	raw[0] = byte(CodeAccessRequest)
	raw[3] = HeaderSize
	for n := 0; n < HeaderSize; n++ {
		_, err := DecodeHeader(raw[:n])
		if !errors.Is(err, ErrHeaderShort) {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if DiscardReason(err) != ReasonMalformedHeader {
			t.Fatalf("n=%d reason=%s", n, DiscardReason(err))
		}
	}
}

func TestDecodeHeaderIgnoresTrailing(t *testing.T) {
	t.Parallel()
	raw := append(minPacket(CodeAccountingRequest, 9), 0xff, 0xff)
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Code != CodeAccountingRequest || h.Identifier != 9 || h.Length != HeaderSize {
		t.Fatalf("got %#v", h)
	}
}

func TestDecodeRejectsDeclaredShorterThanHeader(t *testing.T) {
	t.Parallel()
	raw := minPacket(CodeAccessRequest, 1)
	raw[2], raw[3] = 0, 19
	_, err := Decode(raw)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("err=%v", err)
	}
	if DiscardReason(err) != ReasonInvalidLength {
		t.Fatalf("reason=%s", DiscardReason(err))
	}
}

func TestDecodeRejectsDeclaredLongerThanDatagram(t *testing.T) {
	t.Parallel()
	raw := minPacket(CodeAccessRequest, 1)
	raw[2], raw[3] = 0, 30
	_, err := Decode(raw)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeRejectsDeclaredOverRFCMax(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 4097)
	raw[0] = byte(CodeAccessRequest)
	raw[2] = 0x10
	raw[3] = 0x01 // 4097
	_, err := Decode(raw)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeIgnoresTrailingPadding(t *testing.T) {
	t.Parallel()
	raw := append(minPacket(CodeAccessAccept, 3), 0xff, 0x00, 0xaa)
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != CodeAccessAccept || got.Identifier != 3 || got.Attributes.Len() != 0 {
		t.Fatalf("got %s", got)
	}
	enc, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, raw[:HeaderSize]) {
		t.Fatalf("encoded %x", enc)
	}
}

func TestDecodeUnknownCodePreserved(t *testing.T) {
	t.Parallel()
	raw := minPacket(12, 1)
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != 12 || got.Code.Known() || got.Code.Advertised() {
		t.Fatalf("code=%d known=%v", got.Code, got.Code.Known())
	}
}

func TestDecodeAccessChallenge(t *testing.T) {
	t.Parallel()
	raw := minPacket(CodeAccessChallenge, 4)
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != CodeAccessChallenge || got.Code.Advertised() {
		t.Fatalf("challenge advertised or lost: %s", got)
	}
}

func TestRoundTripWithAttributes(t *testing.T) {
	t.Parallel()
	var auth [16]byte
	for i := range auth {
		auth[i] = byte(i + 1)
	}
	in := Packet{
		Code:          CodeAccessRequest,
		Identifier:    7,
		Authenticator: auth,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeProxyState, Value: []byte{1}},
			{Type: attribute.TypeProxyState, Value: []byte{2}},
			{Type: 200, Value: []byte{9, 8, 7}},
			{Type: attribute.TypeVendorSpecific, Value: []byte{0, 0, 0, 9, 1, 3, 'x'}},
		},
	}
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != HeaderSize+in.Attributes.WireSize() {
		t.Fatalf("len=%d", len(wire))
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !packetsEqual(got, in) {
		t.Fatalf("got %s", got)
	}
}

func TestDecodeDoesNotAliasDatagram(t *testing.T) {
	t.Parallel()
	p := Packet{
		Code:       CodeAccessRequest,
		Identifier: 1,
		Attributes: attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("abc")}},
	}
	wire, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire[HeaderSize+2] = 'Z'
	if !bytes.Equal(got.Attributes[0].Value, []byte("abc")) {
		t.Fatal("attribute aliased datagram")
	}
}

func TestDecodeAttributeOverflow(t *testing.T) {
	t.Parallel()
	raw := minPacket(CodeAccessRequest, 1)
	raw = append(raw, 1, 10, 1, 2)
	raw[2], raw[3] = 0, byte(len(raw))
	_, err := Decode(raw)
	if !errors.Is(err, ErrAttributeOverflow) {
		t.Fatalf("err=%v", err)
	}
	if DiscardReason(err) != ReasonInvalidLength {
		t.Fatalf("reason=%s", DiscardReason(err))
	}
}

func TestDecodeBoundedTighterCap(t *testing.T) {
	t.Parallel()
	p := Packet{
		Code:       CodeAccessRequest,
		Identifier: 1,
		Attributes: attribute.RawSet{{Type: 1, Value: bytes.Repeat([]byte{'a'}, 20)}},
	}
	wire, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBounded(wire, Bounds{MaxPacketBytes: 32}); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("tighter cap: %v (len=%d)", err, len(wire))
	}
	got, err := DecodeBounded(wire, Bounds{MaxPacketBytes: len(wire)})
	if err != nil || got.Attributes.Len() != 1 {
		t.Fatalf("exact cap: %v", err)
	}
}

func TestEncodeFailsWhenOverMax(t *testing.T) {
	t.Parallel()
	p := Packet{Code: CodeAccessAccept, Identifier: 1}
	p.Attributes = attribute.RawSet{{Type: 1, Value: bytes.Repeat([]byte{'a'}, 20)}}
	_, err := EncodeBounded(p, Bounds{MaxPacketBytes: 24})
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("err=%v", err)
	}
}

func TestEncodeMaxPacket(t *testing.T) {
	t.Parallel()
	// 4096-byte packet: 15×255-octet TLVs + one 251-octet TLV.
	attrs := make(attribute.RawSet, 0, 16)
	for i := 0; i < 15; i++ {
		attrs = append(attrs, attribute.Raw{Type: 18, Value: bytes.Repeat([]byte{0x5a}, 253)})
	}
	attrs = append(attrs, attribute.Raw{Type: 18, Value: bytes.Repeat([]byte{0x5a}, 249)})
	p := Packet{Code: CodeAccessReject, Identifier: 2, Attributes: attrs}
	wire, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != MaxPacketBytes {
		t.Fatalf("len=%d", len(wire))
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Attributes.Len() != 16 {
		t.Fatalf("attrs=%d", got.Attributes.Len())
	}
}

func TestFormatNeverPrintsSecretValues(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-PAP-SECRET-xx"
	var auth [16]byte
	copy(auth[:], canary)
	p := Packet{
		Code:          CodeAccessRequest,
		Identifier:    1,
		Authenticator: auth,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserPassword, Value: []byte(canary)},
		},
	}
	blob := fmt.Sprintf("%v %s %#v", p, p, p)
	if strings.Contains(blob, canary) {
		t.Fatalf("secret leaked through packet formatting")
	}
}

func minPacket(code Code, id uint8) []byte {
	raw := make([]byte, HeaderSize)
	raw[0] = byte(code)
	raw[1] = id
	raw[3] = HeaderSize
	return raw
}

func packetsEqual(a, b Packet) bool {
	if a.Code != b.Code || a.Identifier != b.Identifier || a.Authenticator != b.Authenticator {
		return false
	}
	if a.Attributes.Len() != b.Attributes.Len() {
		return false
	}
	for i := range a.Attributes {
		if a.Attributes[i].Type != b.Attributes[i].Type || !bytes.Equal(a.Attributes[i].Value, b.Attributes[i].Value) {
			return false
		}
	}
	return true
}

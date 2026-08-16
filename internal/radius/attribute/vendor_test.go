package attribute

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseVSARoundTrip(t *testing.T) {
	t.Parallel()
	in := VSA{Vendor: 9, Payload: []byte{0x01, 0x07, 'h', 'e', 'l', 'l', 'o'}}
	raw, err := in.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if raw.Type != TypeVendorSpecific {
		t.Fatalf("type=%d", raw.Type)
	}
	got, err := ParseVSA(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vendor != 9 || !bytes.Equal(got.Payload, in.Payload) {
		t.Fatalf("got vendor=%d payload_len=%d", got.Vendor, len(got.Payload))
	}
}

func TestParseVSAUnknownVendorPreserved(t *testing.T) {
	t.Parallel()
	raw := Raw{Type: TypeVendorSpecific, Value: []byte{0x00, 0x00, 0x30, 0x39, 0xaa, 0xbb}}
	got, err := ParseVSA(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vendor != 0x3039 || !bytes.Equal(got.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("vendor=%#x payload_len=%d", got.Vendor, len(got.Payload))
	}
}

func TestParseVSAEmptyPayload(t *testing.T) {
	t.Parallel()
	raw := Raw{Type: TypeVendorSpecific, Value: []byte{0, 0, 0, 1}}
	got, err := ParseVSA(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vendor != 1 || got.Payload != nil {
		t.Fatalf("vendor=%d payload=%v", got.Vendor, got.Payload)
	}
}

func TestParseVSARejectsNonVSAAndShort(t *testing.T) {
	t.Parallel()
	if _, err := ParseVSA(Raw{Type: TypeUserName, Value: []byte("x")}); !errors.Is(err, ErrNotVSA) {
		t.Fatalf("not vsa: %v", err)
	}
	if _, err := ParseVSA(Raw{Type: TypeVendorSpecific, Value: []byte{1, 2, 3}}); !errors.Is(err, ErrVSAShort) {
		t.Fatalf("short: %v", err)
	}
	if _, err := ParseVSA(Raw{Type: TypeVendorSpecific}); !errors.Is(err, ErrVSAShort) {
		t.Fatalf("empty: %v", err)
	}
}

func TestVSARawRejectsLongPayload(t *testing.T) {
	t.Parallel()
	_, err := (VSA{Vendor: 1, Payload: bytes.Repeat([]byte{1}, MaxValueLength-vendorIDSize+1)}).Raw()
	if !errors.Is(err, ErrVSAValueLong) {
		t.Fatalf("err=%v", err)
	}
}

func TestParseVendorTLVsRoundTripAndUnknown(t *testing.T) {
	t.Parallel()
	in := []VendorTLV{
		{Type: VendorTypeMSCHAPChallenge, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Type: 99, Value: []byte{0xaa}},
	}
	payload, err := EncodeVendorTLVs(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseVendorTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Type != VendorTypeMSCHAPChallenge || !bytes.Equal(got[0].Value, in[0].Value) {
		t.Fatalf("got=%+v", got)
	}
	if got[1].Type != 99 || !bytes.Equal(got[1].Value, []byte{0xaa}) {
		t.Fatalf("unknown type not preserved: %+v", got[1])
	}
}

func TestParseVendorTLVsMalformed(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		{0x01},
		{0x01, 0x00},
		{0x01, 0x01},
		{0x01, 0x05, 0xaa},
	}
	for i, payload := range cases {
		if _, err := ParseVendorTLVs(payload); !errors.Is(err, ErrVendorTLVMalformed) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

func TestMicrosoftVSAAndSecret(t *testing.T) {
	t.Parallel()
	raw, err := MicrosoftVSA(VendorTypeMSCHAPChallenge, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	if !MicrosoftSecret(raw) {
		t.Fatal("challenge must be secret")
	}
	cisco, err := (VSA{Vendor: 9, Payload: []byte{0x01, 0x03, 'x'}}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	if MicrosoftSecret(cisco) {
		t.Fatal("Cisco VSA is not Microsoft secret")
	}
	if MicrosoftSecret(Raw{Type: TypeUserName, Value: []byte("a")}) {
		t.Fatal("User-Name")
	}
}

func TestPacketKeepsMalformedVSARaw(t *testing.T) {
	t.Parallel()
	wire := []byte{TypeVendorSpecific, 4, 0, 1}
	got, err := Decode(wire, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 1 || got[0].Type != TypeVendorSpecific {
		t.Fatalf("lost raw vsa")
	}
	if _, err := ParseVSA(got[0]); !errors.Is(err, ErrVSAShort) {
		t.Fatalf("parse: %v", err)
	}
}

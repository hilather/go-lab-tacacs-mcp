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

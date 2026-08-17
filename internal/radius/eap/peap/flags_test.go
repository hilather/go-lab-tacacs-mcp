package peap

import (
	"bytes"
	"testing"
)

func TestEncodeStartHasSFlagAndVersion0(t *testing.T) {
	t.Parallel()
	got := EncodeStart()
	if !bytes.Equal(got, []byte{FlagStart | Version0}) {
		t.Fatalf("start=%x", got)
	}
	p, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Start || p.LengthIncluded || p.MoreFragments || p.Version != Version0 || len(p.TLSData) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestParseEncodeRoundTripLengthAndMore(t *testing.T) {
	t.Parallel()
	in := Payload{
		LengthIncluded: true,
		MoreFragments:  true,
		Version:        Version0,
		TLSMessageLen:  8,
		TLSData:        []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03},
	}
	raw := Encode(in)
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LengthIncluded || !got.MoreFragments || got.Start || got.TLSMessageLen != 8 {
		t.Fatalf("%+v", got)
	}
	if !bytes.Equal(got.TLSData, in.TLSData) {
		t.Fatalf("tls=%x", got.TLSData)
	}
	if !bytes.Equal(Encode(got), raw) {
		t.Fatalf("re-encode drifted")
	}
}

func TestParseRejectsEmptyAndShortLength(t *testing.T) {
	t.Parallel()
	if _, err := Parse(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := Parse([]byte{FlagLength}); err == nil {
		t.Fatal("L without length")
	}
}

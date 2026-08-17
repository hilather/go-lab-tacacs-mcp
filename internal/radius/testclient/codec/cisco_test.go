package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestIndependentCiscoAVPairGolden(t *testing.T) {
	t.Parallel()
	bin, err := os.ReadFile(protocolFile(t, "radius", "cisco", "avpair-priv-lvl.bin"))
	if err != nil {
		t.Fatal(err)
	}
	metaRaw, err := os.ReadFile(protocolFile(t, "radius", "cisco", "avpair-priv-lvl.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ValueHex string `json:"value_hex"`
		Text     string `json:"text"`
		RawYAML  struct {
			ValueHex string `json:"value_hex"`
		} `json:"raw_yaml"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bin) != meta.ValueHex {
		t.Fatal("independent fixture bin/json mismatch")
	}
	vsa, err := ParseVSA(Attr{Type: TypeVendorSpecific, Value: bin})
	if err != nil {
		t.Fatal(err)
	}
	if vsa.Vendor != VendorCisco {
		t.Fatalf("vendor=%d", vsa.Vendor)
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil || len(tlvs) != 1 || tlvs[0].Type != TypeCiscoAVPair || string(tlvs[0].Value) != meta.Text {
		t.Fatalf("tlvs=%v err=%v", tlvs, err)
	}
	named, err := EncodeCiscoAVPair(meta.Text)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := hex.DecodeString(meta.RawYAML.ValueHex)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeVendorTLVs([]VendorTLV{{Type: TypeCiscoAVPair, Value: inner}})
	if err != nil {
		t.Fatal(err)
	}
	rawForm, err := (VSA{Vendor: VendorCisco, Payload: payload}).Attr()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(named.Value, rawForm.Value) || !bytes.Equal(named.Value, bin) {
		t.Fatalf("named=%x raw=%x bin=%x", named.Value, rawForm.Value, bin)
	}
	got, err := DecodeCiscoAVPairs(named)
	if err != nil || len(got) != 1 || got[0] != meta.Text {
		t.Fatalf("decode=%v err=%v", got, err)
	}
}

func TestIndependentCiscoAVPairEdges(t *testing.T) {
	t.Parallel()
	multi, err := os.ReadFile(protocolFile(t, "radius", "cisco", "avpair-multi.bin"))
	if err != nil {
		t.Fatal(err)
	}
	vsa, err := ParseVSA(Attr{Type: TypeVendorSpecific, Value: multi})
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil || len(tlvs) != 2 || string(tlvs[1].Value) != "shell:priv-lvl=7" {
		t.Fatalf("multi=%v err=%v", tlvs, err)
	}

	unk, err := os.ReadFile(protocolFile(t, "radius", "cisco", "avpair-unknown-type.bin"))
	if err != nil {
		t.Fatal(err)
	}
	vsa, err = ParseVSA(Attr{Type: TypeVendorSpecific, Value: unk})
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err = ParseVendorTLVs(vsa.Payload)
	if err != nil || len(tlvs) != 1 || tlvs[0].Type != 2 {
		t.Fatalf("unknown=%v err=%v", tlvs, err)
	}
	pairs, err := DecodeCiscoAVPairs(Attr{Type: TypeVendorSpecific, Value: unk})
	if err != nil || len(pairs) != 0 {
		t.Fatalf("unknown must stay unnamed: %v %v", pairs, err)
	}

	for _, name := range []string{"avpair-leftover.bin", "avpair-length-1.bin", "avpair-overflow.bin"} {
		body, err := os.ReadFile(protocolFile(t, "radius", "cisco", name))
		if err != nil {
			t.Fatal(err)
		}
		vsa, err := ParseVSA(Attr{Type: TypeVendorSpecific, Value: body})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseVendorTLVs(vsa.Payload); !errors.Is(err, ErrVendorTLV) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestIndependentCiscoAVPairEmptyAndMax(t *testing.T) {
	t.Parallel()
	empty, err := EncodeCiscoAVPair("")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCiscoAVPairs(empty)
	if err != nil || len(got) != 1 || got[0] != "" {
		t.Fatalf("empty=%v err=%v", got, err)
	}
	_, err = EncodeCiscoAVPair(string(bytes.Repeat([]byte{'x'}, MaxValue-5)))
	if !errors.Is(err, ErrVendorTLVLong) {
		t.Fatalf("too long: %v", err)
	}
}

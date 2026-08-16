package attribute

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVendorTLVsCiscoAVPairGolden(t *testing.T) {
	t.Parallel()
	raw, meta := loadCiscoFixture(t, "avpair-priv-lvl.bin", "avpair-priv-lvl.json")
	if raw.hex != meta.ValueHex {
		t.Fatalf("bin/json hex mismatch")
	}
	vsa, err := ParseVSA(Raw{Type: TypeVendorSpecific, Value: raw.bytes})
	if err != nil {
		t.Fatal(err)
	}
	if vsa.Vendor != VendorCisco {
		t.Fatalf("vendor=%d", vsa.Vendor)
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 1 || tlvs[0].Type != TypeCiscoAVPair || string(tlvs[0].Value) != meta.Text {
		t.Fatalf("tlvs=%v text=%q", tlvs, meta.Text)
	}
	pairs, err := DecodeCiscoAVPairs(Raw{Type: TypeVendorSpecific, Value: raw.bytes})
	if err != nil || len(pairs) != 1 || pairs[0] != meta.Text {
		t.Fatalf("decode=%v err=%v", pairs, err)
	}
}

func TestNamedAndRawCiscoAVPairSameWire(t *testing.T) {
	t.Parallel()
	_, meta := loadCiscoFixture(t, "avpair-priv-lvl.bin", "avpair-priv-lvl.json")
	named, err := EncodeCiscoAVPair(meta.NamedYAML.Value)
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
	rawForm, err := (VSA{Vendor: VendorCisco, Payload: payload}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(named.Value, rawForm.Value) {
		t.Fatalf("named=%x raw=%x", named.Value, rawForm.Value)
	}
	want, err := hex.DecodeString(meta.ValueHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(named.Value, want) {
		t.Fatalf("wire=%x want=%x", named.Value, want)
	}
}

func TestParseVendorTLVsMultipleAndUnknown(t *testing.T) {
	t.Parallel()
	multi := readCiscoBin(t, "avpair-multi.bin")
	vsa, err := ParseVSA(Raw{Type: TypeVendorSpecific, Value: multi})
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 2 || string(tlvs[0].Value) != "shell:priv-lvl=15" || string(tlvs[1].Value) != "shell:priv-lvl=7" {
		t.Fatalf("multi=%v", tlvs)
	}
	pairs, err := DecodeCiscoAVPairs(Raw{Type: TypeVendorSpecific, Value: multi})
	if err != nil || len(pairs) != 2 {
		t.Fatalf("pairs=%v err=%v", pairs, err)
	}

	unk := readCiscoBin(t, "avpair-unknown-type.bin")
	vsa, err = ParseVSA(Raw{Type: TypeVendorSpecific, Value: unk})
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err = ParseVendorTLVs(vsa.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 1 || tlvs[0].Type != 2 || string(tlvs[0].Value) != "abc" {
		t.Fatalf("unknown=%v", tlvs)
	}
	if _, ok := Builtin().LookupKey(Key{Vendor: VendorCisco, Code: 2, Space: SpaceVSA}); ok {
		t.Fatal("unknown Cisco type must stay unnamed")
	}
	pairs, err = DecodeCiscoAVPairs(Raw{Type: TypeVendorSpecific, Value: unk})
	if err != nil || len(pairs) != 0 {
		t.Fatalf("unknown must not decode as Cisco-AVPair: %v %v", pairs, err)
	}
}

func TestParseVendorTLVsEdges(t *testing.T) {
	t.Parallel()
	emptyVSA, err := ParseVSA(Raw{Type: TypeVendorSpecific, Value: readCiscoBin(t, "avpair-empty.bin")})
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := ParseVendorTLVs(emptyVSA.Payload)
	if err != nil || len(tlvs) != 1 || tlvs[0].Type != TypeCiscoAVPair || len(tlvs[0].Value) != 0 {
		t.Fatalf("empty=%v err=%v", tlvs, err)
	}

	tlvs, err = ParseVendorTLVs(nil)
	if err != nil || len(tlvs) != 0 {
		t.Fatalf("nil payload: %v %v", tlvs, err)
	}

	cases := []struct {
		name string
		file string
	}{
		{"leftover", "avpair-leftover.bin"},
		{"length-1", "avpair-length-1.bin"},
		{"overflow", "avpair-overflow.bin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vsa, err := ParseVSA(Raw{Type: TypeVendorSpecific, Value: readCiscoBin(t, tc.file)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseVendorTLVs(vsa.Payload); !errors.Is(err, ErrVendorTLV) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	if _, err := ParseVendorTLVs([]byte{1}); !errors.Is(err, ErrVendorTLV) {
		t.Fatalf("single leftover byte: %v", err)
	}
}

func TestEncodeVendorTLVsRejectsTooLong(t *testing.T) {
	t.Parallel()
	_, err := EncodeVendorTLVs([]VendorTLV{{Type: 1, Value: bytes.Repeat([]byte{'a'}, MaxVendorTLVValue+1)}})
	if !errors.Is(err, ErrVendorTLVLong) {
		t.Fatalf("err=%v", err)
	}
	_, err = EncodeCiscoAVPair(string(bytes.Repeat([]byte{'b'}, MaxVendorTLVValue+1)))
	if !errors.Is(err, ErrVendorTLVLong) {
		t.Fatalf("encode named: %v", err)
	}
	ok, err := EncodeCiscoAVPair(string(bytes.Repeat([]byte{'c'}, MaxVendorTLVValue)))
	if err != nil || ok.Type != TypeVendorSpecific {
		t.Fatalf("max legal: %v %+v", err, ok)
	}
}

func TestParseVendorTLVsPreservesOrderAndDuplicates(t *testing.T) {
	t.Parallel()
	payload, err := EncodeVendorTLVs([]VendorTLV{
		{Type: TypeCiscoAVPair, Value: []byte("one")},
		{Type: 9, Value: []byte("raw")},
		{Type: TypeCiscoAVPair, Value: []byte("one")},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseVendorTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || string(got[0].Value) != "one" || got[1].Type != 9 || string(got[2].Value) != "one" {
		t.Fatalf("got=%v", got)
	}
}

func TestCiscoAVPairRoundTripAndSummary(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-CISCO-AVPAIR-zz"
	raw, err := EncodeCiscoAVPair(canary)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCiscoAVPairs(raw)
	if err != nil || len(got) != 1 || got[0] != canary {
		t.Fatalf("got=%v err=%v", got, err)
	}
	sum := Builtin().Summarize(raw)
	if !sum.Known || sum.Vendor != VendorCisco || sum.Name != NameCiscoAVPair || sum.Sensitivity != SensitivityRestricted {
		t.Fatalf("sum=%+v", sum)
	}
	if strings.Contains(sum.String(), canary) {
		t.Fatal("summary leaked Cisco-AVPair value")
	}
	blob := fmt.Sprintf("%v %#v %s", raw, raw, VSA{Vendor: VendorCisco, Payload: []byte(canary)})
	if strings.Contains(blob, canary) {
		t.Fatalf("value leaked: %s", blob)
	}
}

func TestVendorTLVFormatNeverPrintsValue(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-VTLV-SECRET-aa"
	tlv := VendorTLV{Type: TypeCiscoAVPair, Value: []byte(canary)}
	if strings.Contains(fmt.Sprintf("%v %#v %s", tlv, tlv, tlv), canary) {
		t.Fatal("VendorTLV leaked value")
	}
}

func TestDecodeCiscoAVPairsNonCiscoVendor(t *testing.T) {
	t.Parallel()
	raw, err := (VSA{Vendor: 311, Payload: []byte{1, 5, 'x', 'y', 'z'}}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCiscoAVPairs(raw)
	if err != nil || got != nil {
		t.Fatalf("microsoft vsa: %v %v", got, err)
	}
}

type ciscoPrivMeta struct {
	ValueHex  string `json:"value_hex"`
	Text      string `json:"text"`
	NamedYAML struct {
		Value string `json:"value"`
	} `json:"named_yaml"`
	RawYAML struct {
		ValueHex string `json:"value_hex"`
	} `json:"raw_yaml"`
}

type ciscoBin struct {
	bytes []byte
	hex   string
}

func loadCiscoFixture(t *testing.T, binName, jsonName string) (ciscoBin, ciscoPrivMeta) {
	t.Helper()
	b := readCiscoBin(t, binName)
	raw, err := os.ReadFile(ciscoPath(t, jsonName))
	if err != nil {
		t.Fatal(err)
	}
	var meta ciscoPrivMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return ciscoBin{bytes: b, hex: hex.EncodeToString(b)}, meta
}

func readCiscoBin(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(ciscoPath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ciscoPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		cand := filepath.Join(dir, "testdata", "protocol", "radius", "cisco", name)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("testdata/protocol/radius/cisco/%s not found", name)
	return ""
}

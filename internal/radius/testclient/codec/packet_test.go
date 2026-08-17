package codec

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

type radiusCatalog struct {
	Packets []struct {
		Name          string `json:"name"`
		Path          string `json:"path"`
		RawHex        string `json:"raw_hex"`
		Len           int    `json:"len"`
		Declared      int    `json:"declared"`
		Code          uint8  `json:"code"`
		Identifier    uint8  `json:"identifier"`
		Authenticator string `json:"authenticator_hex"`
		Attributes    []struct {
			Type     uint8  `json:"type"`
			ValueHex string `json:"value_hex"`
		} `json:"attributes"`
		Known      bool `json:"known"`
		Advertised bool `json:"advertised"`
	} `json:"packets"`
	Negatives []struct {
		Name   string `json:"name"`
		Path   string `json:"path"`
		RawHex string `json:"raw_hex"`
		Reason string `json:"reason"`
	} `json:"negatives"`
}

func TestIndependentCatalogBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat radiusCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Packets) < 8 || len(cat.Negatives) < 6 {
		t.Fatalf("catalog packets=%d negatives=%d", len(cat.Packets), len(cat.Negatives))
	}
	for _, p := range cat.Packets {
		wire, err := hex.DecodeString(p.RawHex)
		if err != nil {
			t.Fatalf("%s: hex: %v", p.Name, err)
		}
		if len(wire) != p.Len {
			t.Fatalf("%s len %d vs %d", p.Name, len(wire), p.Len)
		}
		bin, err := os.ReadFile(protocolFile(t, "radius", p.Path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bin, wire) {
			t.Fatalf("%s bin mismatch", p.Name)
		}
		got, err := Decode(wire)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if byte(got.Code) != p.Code || got.Identifier != p.Identifier {
			t.Fatalf("%s code/id %d/%d", p.Name, got.Code, got.Identifier)
		}
		if got.Code.Known() != p.Known || got.Code.Advertised() != p.Advertised {
			t.Fatalf("%s known/advertised %v/%v", p.Name, got.Code.Known(), got.Code.Advertised())
		}
		wantAuth, err := hex.DecodeString(p.Authenticator)
		if err != nil {
			t.Fatalf("%s auth hex: %v", p.Name, err)
		}
		if !bytes.Equal(got.Authenticator[:], wantAuth) {
			t.Fatalf("%s authenticator mismatch", p.Name)
		}
		if len(got.Attrs) != len(p.Attributes) {
			t.Fatalf("%s attrs %d vs %d", p.Name, len(got.Attrs), len(p.Attributes))
		}
		for i, want := range p.Attributes {
			val, err := hex.DecodeString(want.ValueHex)
			if err != nil {
				t.Fatalf("%s attr %d hex: %v", p.Name, i, err)
			}
			if got.Attrs[i].Type != want.Type || !bytes.Equal(got.Attrs[i].Value, val) {
				t.Fatalf("%s attr %d type/len mismatch type=%d", p.Name, i, got.Attrs[i].Type)
			}
		}
		enc, err := Encode(got)
		if err != nil {
			t.Fatalf("%s encode: %v", p.Name, err)
		}
		if !bytes.Equal(enc, wire[:p.Declared]) {
			t.Fatalf("%s encode mismatch declared=%d", p.Name, p.Declared)
		}
	}
	for _, n := range cat.Negatives {
		wire, err := hex.DecodeString(n.RawHex)
		if err != nil {
			t.Fatalf("%s: hex: %v", n.Name, err)
		}
		bin, err := os.ReadFile(protocolFile(t, "radius", n.Path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bin, wire) {
			t.Fatalf("%s bin mismatch", n.Name)
		}
		_, err = Decode(wire)
		switch n.Reason {
		case "malformed_header":
			if !errors.Is(err, ErrHeaderShort) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		case "invalid_length":
			if err == nil || !(errors.Is(err, ErrInvalidLength) || errors.Is(err, ErrAttrOverflow) || errors.Is(err, ErrAttrLength) || errors.Is(err, ErrTooManyAttrs) || errors.Is(err, ErrAttrBudget) || errors.Is(err, ErrAttrValueLong)) {
				t.Fatalf("%s: %v", n.Name, err)
			}
		default:
			t.Fatalf("%s unknown reason %s", n.Name, n.Reason)
		}
	}
}

func TestIndependentVSAFraming(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "packets", "access-request-vsa.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := First(got.Attrs, TypeVendorSpecific)
	if !ok {
		t.Fatal("missing VSA")
	}
	vsa, err := ParseVSA(a)
	if err != nil {
		t.Fatal(err)
	}
	if vsa.Vendor != 9 || len(vsa.Payload) == 0 {
		t.Fatalf("vendor=%d payload_len=%d", vsa.Vendor, len(vsa.Payload))
	}
	enc, err := vsa.Attr()
	if err != nil {
		t.Fatal(err)
	}
	if enc.Type != TypeVendorSpecific || !bytes.Equal(enc.Value, a.Value) {
		t.Fatal("vsa re-encode bytes mismatch")
	}
}

func TestIndependentFuzzSeedFilesExist(t *testing.T) {
	t.Parallel()
	dir := protocolFile(t, "radius", "fuzz")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		n++
	}
	if n < 10 {
		t.Fatalf("expected at least 10 fuzz seeds, got %d", n)
	}
}

func TestFormatNeverPrintsSecretValues(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-PAP-SECRET-xx"
	var auth [16]byte
	copy(auth[:], canary)
	p := Packet{
		Code:          AccessRequest,
		Identifier:    1,
		Authenticator: auth,
		Attrs: []Attr{
			{Type: TypeUserPassword, Value: []byte(canary)},
		},
	}
	vsa := VSA{Vendor: 9, Payload: []byte(canary)}
	blob := fmt.Sprintf("%v %s %#v %v %s %#v %v %s %#v", p, p, p, p.Attrs[0], p.Attrs[0], p.Attrs[0], vsa, vsa, vsa)
	if strings.Contains(blob, canary) {
		t.Fatalf("secret leaked through formatting")
	}
}

func TestCodeClassification(t *testing.T) {
	t.Parallel()
	if !AccessRequest.Known() || !AccessRequest.Advertised() || !AccessRequest.AccessFamily() {
		t.Fatal("access-request")
	}
	if !AccessChallenge.Advertised() || !AccessChallenge.Known() {
		t.Fatal("challenge must be advertised")
	}
	if !AccountingRequest.AccountingFamily() || AccountingRequest.AccessFamily() {
		t.Fatal("acct family")
	}
	if Code(12).Known() || Code(12).Advertised() {
		t.Fatal("unknown code")
	}
}

package codec_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func protocolFile(t testing.TB, elem ...string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		cand := filepath.Join(append([]string{dir, "testdata", "protocol"}, elem...)...)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("testdata/protocol/%s not found", filepath.Join(elem...))
	return ""
}

func TestPeerEncodeDecodeCatalogBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "radius", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		Packets []struct {
			Name     string `json:"name"`
			RawHex   string `json:"raw_hex"`
			Declared int    `json:"declared"`
		} `json:"packets"`
	}
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Packets) < 8 {
		t.Fatalf("catalog packets=%d", len(cat.Packets))
	}
	for _, p := range cat.Packets {
		wire, err := hex.DecodeString(p.RawHex)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		prod, err := codec.Decode(wire)
		if err != nil {
			t.Fatalf("%s production decode: %v", p.Name, err)
		}
		indep, err := tcodec.Decode(wire)
		if err != nil {
			t.Fatalf("%s testclient decode: %v", p.Name, err)
		}
		prodEnc, err := codec.Encode(prod)
		if err != nil {
			t.Fatalf("%s production encode: %v", p.Name, err)
		}
		indepEnc, err := tcodec.Encode(indep)
		if err != nil {
			t.Fatalf("%s testclient encode: %v", p.Name, err)
		}
		want := wire[:p.Declared]
		if !bytes.Equal(prodEnc, want) {
			t.Fatalf("%s production encode mismatch", p.Name)
		}
		if !bytes.Equal(indepEnc, want) {
			t.Fatalf("%s testclient encode mismatch", p.Name)
		}
		if !bytes.Equal(prodEnc, indepEnc) {
			t.Fatalf("%s production vs testclient encode bytes differ", p.Name)
		}
	}
}

func TestPeerConstructedPacketBytes(t *testing.T) {
	t.Parallel()
	var auth [16]byte
	for i := range auth {
		auth[i] = byte(i + 3)
	}
	user := []byte("lab-admin")
	proxyA := []byte{1}
	proxyB := []byte{2}
	unknown := []byte{9, 8, 7}
	vsaVal := []byte{0, 0, 0, 9, 1, 3, 'x'}

	prodEnc, err := codec.Encode(codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    7,
		Authenticator: auth,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: user},
			{Type: attribute.TypeProxyState, Value: proxyA},
			{Type: attribute.TypeProxyState, Value: proxyB},
			{Type: 200, Value: unknown},
			{Type: attribute.TypeVendorSpecific, Value: vsaVal},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	indepEnc, err := tcodec.Encode(tcodec.Packet{
		Code:          tcodec.AccessRequest,
		Identifier:    7,
		Authenticator: auth,
		Attrs: []tcodec.Attr{
			{Type: tcodec.TypeUserName, Value: user},
			{Type: tcodec.TypeProxyState, Value: proxyA},
			{Type: tcodec.TypeProxyState, Value: proxyB},
			{Type: 200, Value: unknown},
			{Type: tcodec.TypeVendorSpecific, Value: vsaVal},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prodEnc, indepEnc) {
		t.Fatalf("constructed packet bytes differ\nprod %x\nindep %x", prodEnc, indepEnc)
	}

	// Cross decode: production bytes through testclient and back.
	cross, err := tcodec.Decode(prodEnc)
	if err != nil {
		t.Fatal(err)
	}
	back, err := tcodec.Encode(cross)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, prodEnc) {
		t.Fatal("testclient re-encode of production bytes mismatch")
	}
	prodBack, err := codec.Decode(indepEnc)
	if err != nil {
		t.Fatal(err)
	}
	prodAgain, err := codec.Encode(prodBack)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prodAgain, indepEnc) {
		t.Fatal("production re-encode of testclient bytes mismatch")
	}
}

package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestObfuscateIndependentVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "obfuscation", "rfc8907-section-4.5.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name      string `json:"name"`
			SessionID uint32 `json:"session_id"`
			Version   byte   `json:"version"`
			SeqNo     byte   `json:"seq_no"`
			Key       string `json:"key"`
			PlainHex  string `json:"plain_hex"`
			CipherHex string `json:"cipher_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Vectors {
		plain, err := hex.DecodeString(v.PlainHex)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(v.CipherHex)
		if err != nil {
			t.Fatal(err)
		}
		got := Obfuscate(v.SessionID, v.Version, v.SeqNo, []byte(v.Key), plain)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s got %x want %x", v.Name, got, want)
		}
	}
}

func TestObfuscateWrongSecretAndRoundTrip(t *testing.T) {
	t.Parallel()
	plain := bytes.Repeat([]byte{0x5a}, 17)
	key := []byte("lab-test-shared-secret")
	enc := Obfuscate(0x01020304, 0xc0, 1, key, plain)
	if bytes.Equal(Obfuscate(0x01020304, 0xc0, 1, []byte("other-lab-shared-secret"), enc), plain) {
		t.Fatal("wrong secret recovered plaintext")
	}
	if !bytes.Equal(Obfuscate(0x01020304, 0xc0, 1, key, enc), plain) {
		t.Fatal("round-trip")
	}
}

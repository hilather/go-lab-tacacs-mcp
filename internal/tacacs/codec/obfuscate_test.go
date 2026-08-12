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
	if len(doc.Vectors) < 6 {
		t.Fatalf("vectors=%d", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		plain, err := hex.DecodeString(v.PlainHex)
		if err != nil {
			t.Fatalf("%s plain: %v", v.Name, err)
		}
		want, err := hex.DecodeString(v.CipherHex)
		if err != nil {
			t.Fatalf("%s cipher: %v", v.Name, err)
		}
		got := Obfuscate(v.SessionID, v.Version, v.SeqNo, []byte(v.Key), plain)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s got %x want %x", v.Name, got, want)
		}
		back := Obfuscate(v.SessionID, v.Version, v.SeqNo, []byte(v.Key), got)
		if !bytes.Equal(back, plain) {
			t.Fatalf("%s round-trip", v.Name)
		}
	}
}

func TestObfuscateRoundTrip(t *testing.T) {
	t.Parallel()
	key := []byte("lab-test-shared-secret")
	bodies := [][]byte{
		nil, {}, []byte("x"), []byte("hello"),
		bytes.Repeat([]byte("n"), 17),
		bytes.Repeat([]byte{0x5a}, 64),
		bytes.Repeat([]byte{0x3c}, 1024),
	}
	for _, body := range bodies {
		got := Obfuscate(0x01020304, 0xc0, 1, key, Obfuscate(0x01020304, 0xc0, 1, key, body))
		want := body
		if want == nil {
			want = []byte{}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round-trip len=%d", len(body))
		}
	}
}

func TestObfuscateWrongSecret(t *testing.T) {
	t.Parallel()
	plain := []byte("hello-tacacs")
	enc := Obfuscate(0x01020304, 0xc0, 1, []byte("lab-test-shared-secret"), plain)
	wrong := Obfuscate(0x01020304, 0xc0, 1, []byte("other-lab-shared-secret"), enc)
	if bytes.Equal(wrong, plain) {
		t.Fatal("wrong secret recovered plaintext")
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
}

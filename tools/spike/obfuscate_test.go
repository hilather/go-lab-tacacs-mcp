package spike

import (
	"bytes"
	"testing"
)

func TestObfuscateRoundTrip(t *testing.T) {
	t.Parallel()
	key := []byte("tacacssecret")
	bodies := [][]byte{nil, {}, []byte("x"), []byte("hello"), bytes.Repeat([]byte("n"), 17), bytes.Repeat([]byte{0x5a}, 64), bytes.Repeat([]byte{0x3c}, 1024)}
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

func TestObfuscateKnownVector(t *testing.T) {
	t.Parallel()
	// MD5(01 02 03 04 || "tacacssecret" || c0 || 01) then XOR "hello"
	got := Obfuscate(0x01020304, 0xc0, 1, []byte("tacacssecret"), []byte("hello"))
	want := []byte{0x55, 0x6b, 0x7f, 0x8d, 0xd6}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestObfuscateSecondBlock(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte("x"), 17)
	got := Obfuscate(0x01020304, 0xc0, 1, []byte("tacacssecret"), body)
	// First 16 pad bytes XOR 'x', 17th pad byte 0x14 XOR 'x'
	if got[16] != 'x'^0x14 {
		t.Fatalf("block2 byte = %x", got[16])
	}
}

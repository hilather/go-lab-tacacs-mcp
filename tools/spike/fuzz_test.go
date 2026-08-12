package spike

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzHeader(f *testing.F) {
	dir := filepath.Join("..", "..", "testdata", "protocol", "fuzz", "header")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte{})
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := DecodeHeader(data)
		if err != nil {
			return
		}
		enc := h.Encode()
		if len(enc) != HeaderSize {
			t.Fatalf("encode len %d", len(enc))
		}
		got, err := DecodeHeader(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != h {
			t.Fatalf("round-trip %#v vs %#v", got, h)
		}
		_ = h.BodyBudget()
	})
}

func FuzzObfuscate(f *testing.F) {
	f.Add(uint32(1), byte(0xc0), byte(1), []byte("key"), []byte("body"))
	f.Add(uint32(0), byte(0), byte(0), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, sessionID uint32, version, seq byte, key, body []byte) {
		once := Obfuscate(sessionID, version, seq, key, body)
		twice := Obfuscate(sessionID, version, seq, key, once)
		want := body
		if want == nil {
			want = []byte{}
		}
		if len(twice) != len(want) {
			t.Fatalf("len %d vs %d", len(twice), len(want))
		}
		for i := range twice {
			if twice[i] != want[i] {
				t.Fatalf("round-trip mismatch at %d", i)
			}
		}
	})
}

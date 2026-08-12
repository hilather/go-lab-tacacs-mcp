package codec

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzHeader(f *testing.F) {
	dir := protocolFile(f, "fuzz", "header")
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
		_ = h.BodyBudget(0)
		if _, err := h.AllocateBody(0); err == nil && h.Length > MaxBodyBytes {
			t.Fatalf("allocated over budget length=%d", h.Length)
		}
	})
}

func FuzzObfuscate(f *testing.F) {
	f.Add(uint32(1), byte(0xc0), byte(1), []byte("key"), []byte("body"))
	f.Add(uint32(0), byte(0), byte(0), []byte{}, []byte{})
	f.Add(uint32(0x01020304), byte(0xc0), byte(1), []byte("lab-test-shared-secret"), make([]byte, 17))
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

func FuzzDecodePacket(f *testing.F) {
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
	f.Add(append(h.Encode(), 1, 2, 3, 4), uint32(MaxBodyBytes))
	f.Add(make([]byte, 12), uint32(0))
	huge := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, Length: 0xffffffff}
	f.Add(huge.Encode(), uint32(0))
	f.Fuzz(func(t *testing.T, data []byte, max uint32) {
		_, body, err := DecodePacket(data, max)
		if err != nil {
			if body != nil {
				t.Fatalf("body set on error: %d", len(body))
			}
			return
		}
		cap := ClampMaxBody(max)
		if uint32(len(body)) > cap {
			t.Fatalf("body %d > cap %d", len(body), cap)
		}
	})
}

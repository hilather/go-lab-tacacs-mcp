package codec

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzIndependentPacketDecode(f *testing.F) {
	dir := protocolFile(f, "radius", "fuzz")
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
	f.Add(make([]byte, 19))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			return
		}
		enc, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got.Code != p.Code || got.Identifier != p.Identifier || got.Authenticator != p.Authenticator {
			t.Fatal("header round-trip mismatch")
		}
		if len(got.Attrs) != len(p.Attrs) {
			t.Fatal("attr count mismatch")
		}
	})
}

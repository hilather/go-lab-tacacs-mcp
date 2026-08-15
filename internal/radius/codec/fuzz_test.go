package codec

import (
	"os"
	"path/filepath"
	"testing"
)

func addRadiusSeeds(f *testing.F) {
	f.Helper()
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
}

func FuzzRadiusPacketDecode(f *testing.F) {
	addRadiusSeeds(f)
	f.Add([]byte{})
	f.Add(make([]byte, 19))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			if DiscardReason(err) == "" {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		enc, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) < MinPacketBytes || len(enc) > MaxPacketBytes {
			t.Fatalf("encoded %d", len(enc))
		}
		got, err := Decode(enc)
		if err != nil {
			t.Fatal(err)
		}
		if !packetsEqual(got, p) {
			t.Fatal("round-trip mismatch")
		}
		if p.Attributes.Len() > DefaultMaxAttrs {
			t.Fatalf("attrs %d", p.Attributes.Len())
		}
	})
}

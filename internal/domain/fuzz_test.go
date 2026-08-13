package domain

import (
	"strings"
	"testing"
)

func FuzzParseAVPair(f *testing.F) {
	f.Add("cmd=show")
	f.Add("priv-lvl*15")
	f.Add("=")
	f.Add("*")
	f.Add("")
	f.Add(strings.Repeat("a", 255) + "=")
	f.Fuzz(func(t *testing.T, s string) {
		p, present, err := ParseAVPair(s)
		if err != nil || !present {
			if err != nil && strings.Contains(err.Error(), "unit-test") {
				t.Fatal(err)
			}
			return
		}
		enc, err := p.Encode()
		if err != nil {
			return
		}
		if len(enc) > AVPairMaxEncodedLen {
			t.Fatalf("encoded %d", len(enc))
		}
	})
}

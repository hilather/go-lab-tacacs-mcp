package events

import "testing"

func FuzzDecodeCursor(f *testing.F) {
	f.Add("")
	f.Add("evt_1")
	f.Add("evt_0")
	f.Add("evt_")
	f.Add("1")
	f.Add("evt_18446744073709551615")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := DecodeCursor(s)
		if err != nil {
			if n != 0 {
				t.Fatalf("n=%d on error", n)
			}
			return
		}
		enc := EncodeCursor(n)
		got, err := DecodeCursor(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Fatalf("%d vs %d", got, n)
		}
	})
}

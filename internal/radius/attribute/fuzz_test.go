package attribute

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzRadiusAttributeDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2})
	f.Add([]byte{1, 5, 'a', 'b', 'c'})
	f.Add([]byte{25, 3, 'a', 25, 3, 'b'})
	f.Add([]byte{TypeVendorSpecific, 12, 0, 0, 0, 9, 1, 7, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{1, 0})
	f.Add([]byte{1, 10, 1})
	f.Add([]byte{1})
	f.Add([]byte{TypeUserPassword, 18, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := Decode(data, 0, 0)
		if err != nil {
			if set != nil {
				t.Fatalf("set on error: %d", len(set))
			}
			return
		}
		if set.Len() > DefaultMaxAttributes {
			t.Fatalf("attrs %d", set.Len())
		}
		if set.ValueBytes() > DefaultMaxValueBytes {
			t.Fatalf("value bytes %d", set.ValueBytes())
		}
		enc, err := Encode(set)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(enc, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !rawSetsEqual(got, set) {
			t.Fatal("encode/decode mismatch")
		}
	})
}

func FuzzRadiusVSA(f *testing.F) {
	f.Add([]byte{0, 0, 0, 9, 1, 3, 'x'})
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 260))
	f.Fuzz(func(t *testing.T, data []byte) {
		raw := Raw{Type: TypeVendorSpecific, Value: data}
		v, err := ParseVSA(raw)
		if err != nil {
			if !errors.Is(err, ErrVSAShort) {
				t.Fatalf("err=%v", err)
			}
			return
		}
		out, err := v.Raw()
		if err != nil {
			if errors.Is(err, ErrVSAValueLong) {
				return
			}
			t.Fatal(err)
		}
		if out.Type != TypeVendorSpecific {
			t.Fatalf("type=%d", out.Type)
		}
		got, err := ParseVSA(out)
		if err != nil {
			t.Fatal(err)
		}
		if got.Vendor != v.Vendor || !bytes.Equal(got.Payload, v.Payload) {
			t.Fatal("vsa round-trip mismatch")
		}
		non := Raw{Type: TypeUserName, Value: data}
		if _, err := ParseVSA(non); !errors.Is(err, ErrNotVSA) {
			t.Fatalf("non-vsa: %v", err)
		}
	})
}

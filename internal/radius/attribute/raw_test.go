package attribute

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	in := RawSet{
		{Type: TypeUserName, Value: []byte("lab-admin")},
		{Type: 200, Value: []byte{0x00, 0xff}},
		{Type: TypeUserName, Value: []byte("dup")},
		{Type: TypeVendorSpecific, Value: []byte{0, 0, 0, 9, 1, 3, 'x'}},
		{Type: 99},
	}
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !rawSetsEqual(got, in) {
		t.Fatalf("round-trip %s vs %s", describeSet(got), describeSet(in))
	}
}

func TestDecodePreservesOrderAndDuplicates(t *testing.T) {
	t.Parallel()
	wire := []byte{
		25, 3, 'a',
		25, 3, 'b',
		25, 3, 'a',
	}
	got, err := Decode(wire, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 3 {
		t.Fatalf("len=%d", got.Len())
	}
	dups := got.AllOf(25)
	if dups.Len() != 3 || !bytes.Equal(dups[0].Value, []byte{'a'}) || !bytes.Equal(dups[1].Value, []byte{'b'}) {
		t.Fatalf("dups %s", describeSet(dups))
	}
}

func TestDecodeRejectsShortLength(t *testing.T) {
	t.Parallel()
	for _, wire := range [][]byte{
		{1, 0},
		{1, 1, 'x'},
	} {
		_, err := Decode(wire, 0, 0)
		if !errors.Is(err, ErrLength) {
			t.Fatalf("wire=%x err=%v", wire, err)
		}
	}
}

func TestDecodeRejectsOverflow(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		{1, 10, 1, 2},
		{1},
		{1, 3},
	}
	for _, wire := range cases {
		_, err := Decode(wire, 0, 0)
		if !errors.Is(err, ErrOverflow) {
			t.Fatalf("wire=%x err=%v", wire, err)
		}
	}
}

func TestDecodeBounds(t *testing.T) {
	t.Parallel()
	var many RawSet
	for i := 0; i < DefaultMaxAttributes+1; i++ {
		many = append(many, Raw{Type: 1})
	}
	wire, err := Encode(many)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(wire, 0, 0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("too many: %v", err)
	}
	ok, err := Decode(wire[:DefaultMaxAttributes*2], 0, 0)
	if err != nil || ok.Len() != DefaultMaxAttributes {
		t.Fatalf("cap: len=%d err=%v", ok.Len(), err)
	}

	big := Raw{Type: 4, Value: []byte{1, 2, 3, 4, 5}}
	w, err := Encode(RawSet{big})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(w, 8, 4); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
}

func TestEncodeRejectsLongValue(t *testing.T) {
	t.Parallel()
	_, err := Encode(RawSet{{Type: 1, Value: bytes.Repeat([]byte{'a'}, MaxValueLength+1)}})
	if !errors.Is(err, ErrValueTooLong) {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeDoesNotAliasPayload(t *testing.T) {
	t.Parallel()
	wire := []byte{1, 5, 'a', 'b', 'c'}
	got, err := Decode(wire, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire[2] = 'Z'
	if !bytes.Equal(got[0].Value, []byte("abc")) {
		t.Fatal("value aliased payload")
	}
}

func TestEmptyDecodeEncode(t *testing.T) {
	t.Parallel()
	got, err := Decode(nil, 0, 0)
	if err != nil || got.Len() != 0 {
		t.Fatalf("nil: %v %#v", err, got)
	}
	enc, err := Encode(nil)
	if err != nil || len(enc) != 0 {
		t.Fatalf("encode nil: %v %d", err, len(enc))
	}
}

func TestSensitiveTypes(t *testing.T) {
	t.Parallel()
	if !Sensitive(TypeUserPassword) || !Sensitive(TypeCHAPPassword) || !Sensitive(TypeMessageAuthenticator) {
		t.Fatal("expected secret types")
	}
	if Sensitive(TypeUserName) || Sensitive(TypeVendorSpecific) {
		t.Fatal("username/vsa are not auto-secret for framing")
	}
}

func TestFormatNeverPrintsSecretValues(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-PAP-SECRET-xx"
	r := Raw{Type: TypeUserPassword, Value: []byte(canary)}
	vsa := VSA{Vendor: 9, Payload: []byte(canary)}
	set := RawSet{r, {Type: TypeCHAPPassword, Value: []byte(canary)}}
	blob := fmt.Sprintf("%v %s %#v %v %s %#v %v %s %#v", r, r, r, set, set, set, vsa, vsa, vsa)
	if strings.Contains(blob, canary) {
		t.Fatalf("secret leaked through formatting")
	}
	if !strings.Contains(blob, "type=2") || !strings.Contains(blob, "len=20") {
		t.Fatalf("missing type/len: %s", blob)
	}
}

func rawSetsEqual(a, b RawSet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

func describeSet(s RawSet) string {
	return fmt.Sprintf("count=%d types=%v", s.Len(), typesOf(s))
}

func typesOf(s RawSet) []uint8 {
	out := make([]uint8, len(s))
	for i, a := range s {
		out[i] = a.Type
	}
	return out
}

package codec

import "testing"

func TestPrintableASCII(t *testing.T) {
	t.Parallel()
	if !PrintableASCII(nil) || !PrintableASCII([]byte{}) || !PrintableASCII([]byte("Password:")) {
		t.Fatal("printable accepted values rejected")
	}
	for _, b := range [][]byte{{0x00}, {0x1f}, {0x7f}, {0x80}, {'a', '\n'}, {'\t'}} {
		if PrintableASCII(b) {
			t.Fatalf("accepted %#v", b)
		}
	}
}

package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestCHAPDecode(t *testing.T) {
	t.Parallel()
	chal := bytes.Repeat([]byte{0xab}, 8)
	resp := bytes.Repeat([]byte{0xcd}, 16)
	raw := append(append([]byte{0x07}, chal...), resp...)
	d, err := DecodeCHAPData(raw, 0)
	if err != nil || d.ID != 7 || !bytes.Equal(d.Challenge, chal) || !bytes.Equal(d.Response, resp) {
		t.Fatalf("%#v %v", d, err)
	}
	if _, err := DecodeCHAPData(raw[:1+4+16], 8); !errors.Is(err, ErrCHAPLength) {
		t.Fatalf("short chal: %v", err)
	}
	// Control bytes in data are not printable-ASCII checks.
	ctrl := append(append([]byte{1}, bytes.Repeat([]byte{0x00}, 8)...), bytes.Repeat([]byte{0x7f}, 16)...)
	if _, err := DecodeCHAPData(ctrl, 8); err != nil {
		t.Fatalf("control data: %v", err)
	}
}

func TestMSCHAPExactLengths(t *testing.T) {
	t.Parallel()
	v1 := append(append([]byte{0x01}, bytes.Repeat([]byte{0x11}, 8)...), bytes.Repeat([]byte{0x22}, 49)...)
	if len(v1) != 58 {
		t.Fatalf("v1 fixture %d", len(v1))
	}
	d, err := DecodeMSCHAPv1Data(v1)
	if err != nil || d.ID != 1 || len(d.Challenge) != 8 || len(d.Response) != 49 {
		t.Fatalf("v1 %#v %v", d, err)
	}
	if _, err := DecodeMSCHAPv1Data(v1[:57]); !errors.Is(err, ErrMSCHAPLength) {
		t.Fatalf("v1 short: %v", err)
	}
	if _, err := DecodeMSCHAPv1Data(append(v1, 0)); !errors.Is(err, ErrMSCHAPLength) {
		t.Fatalf("v1 long: %v", err)
	}

	v2 := append(append([]byte{0x02}, bytes.Repeat([]byte{0x33}, 16)...), bytes.Repeat([]byte{0x44}, 49)...)
	if len(v2) != 66 {
		t.Fatalf("v2 fixture %d", len(v2))
	}
	d2, err := DecodeMSCHAPv2Data(v2)
	if err != nil || d2.ID != 2 || len(d2.Challenge) != 16 || len(d2.Response) != 49 {
		t.Fatalf("v2 %#v %v", d2, err)
	}
	if _, err := DecodeMSCHAPv2Data(v1); !errors.Is(err, ErrMSCHAPLength) {
		t.Fatalf("v1 as v2: %v", err)
	}
}

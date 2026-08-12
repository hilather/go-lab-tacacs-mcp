package credentials

import (
	"bytes"
	"testing"
)

func TestSplitCHAPAndMSCHAPLengths(t *testing.T) {
	t.Parallel()
	if _, _, _, err := SplitCHAPData([]byte{1, 2, 3}, 8); err == nil || !isMalformed(err) {
		t.Fatalf("short chap: %v", err)
	}
	chal := bytes.Repeat([]byte{1}, 8)
	resp := bytes.Repeat([]byte{2}, 16)
	data := append([]byte{0x42}, append(chal, resp...)...)
	id, gotCh, gotR, err := SplitCHAPData(data, 8)
	if err != nil || id != 0x42 || !bytes.Equal(gotCh, chal) || !bytes.Equal(gotR, resp) {
		t.Fatalf("chap split id=%d err=%v", id, err)
	}
	if _, _, _, err := SplitMSCHAPv1Data(data); err == nil || !isMalformed(err) {
		t.Fatalf("chap-sized mschapv1: %v", err)
	}
	v1 := append([]byte{9}, append(bytes.Repeat([]byte{3}, 8), bytes.Repeat([]byte{4}, 49)...)...)
	id, gotCh, gotR, err = SplitMSCHAPv1Data(v1)
	if err != nil || id != 9 || len(gotCh) != 8 || len(gotR) != 49 {
		t.Fatalf("mschapv1 split: %v", err)
	}
	if _, _, _, err := SplitMSCHAPv2Data(v1); err == nil || !isMalformed(err) {
		t.Fatalf("v1-sized mschapv2: %v", err)
	}
	v2 := append([]byte{1}, append(bytes.Repeat([]byte{5}, 16), bytes.Repeat([]byte{6}, 49)...)...)
	id, gotCh, gotR, err = SplitMSCHAPv2Data(v2)
	if err != nil || id != 1 || len(gotCh) != 16 || len(gotR) != 49 {
		t.Fatalf("mschapv2 split: %v", err)
	}
}

package spike

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	in := Header{
		Version:   MajorVer << 4,
		Type:      TypeAuthen,
		SeqNo:     1,
		Flags:     FlagSingleConnect,
		SessionID: 0x01020304,
		Length:    32,
	}
	got, err := DecodeHeader(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("got %#v want %#v", got, in)
	}
	if got.Major() != MajorVer || got.Minor() != 0 {
		t.Fatalf("version split major=%d minor=%d", got.Major(), got.Minor())
	}
}

func TestDecodeHeaderShort(t *testing.T) {
	t.Parallel()
	_, err := DecodeHeader(make([]byte, 11))
	if !errors.Is(err, ErrHeaderShort) {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeHeaderIgnoresTrailing(t *testing.T) {
	t.Parallel()
	raw := []byte{0xc0, TypeAuthor, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0xff}
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != TypeAuthor || h.SessionID != 7 {
		t.Fatalf("got %#v", h)
	}
}

func TestDecodeHeaderDoesNotAllocateBody(t *testing.T) {
	t.Parallel()
	raw := []byte{0xc0, TypeAuthen, 1, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Length != 0xffffffff {
		t.Fatalf("length=%d", h.Length)
	}
	if h.BodyBudget() != MaxBodyBytes {
		t.Fatalf("budget=%d", h.BodyBudget())
	}
}

func TestDecodeUnknownTypeAndVersion(t *testing.T) {
	t.Parallel()
	raw := []byte{0x00, 0x99, 1, 0x08, 0, 0, 0, 2, 0, 0, 0, 0}
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != 0x99 || h.Major() != 0 || h.Flags != 0x08 {
		t.Fatalf("got %#v", h)
	}
}

func TestHeaderSeedsFromTestdata(t *testing.T) {
	t.Parallel()
	dir := headerSeedDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		n++
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		h, err := DecodeHeader(raw)
		switch e.Name() {
		case "truncated-11.bin":
			if !errors.Is(err, ErrHeaderShort) {
				t.Fatalf("%s: err=%v", e.Name(), err)
			}
		default:
			if err != nil {
				t.Fatalf("%s: %v", e.Name(), err)
			}
			if e.Name() == "junk-huge-length.bin" && h.BodyBudget() != MaxBodyBytes {
				t.Fatalf("%s budget=%d", e.Name(), h.BodyBudget())
			}
			if len(raw) >= HeaderSize {
				enc := h.Encode()
				if !bytes.Equal(enc, raw[:HeaderSize]) {
					t.Fatalf("%s encode mismatch", e.Name())
				}
			}
		}
	}
	if n < 8 {
		t.Fatalf("expected at least 8 header seeds, got %d", n)
	}
}

func headerSeedDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "protocol", "fuzz", "header")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("header seed dir %s: %v", dir, err)
	}
	return dir
}

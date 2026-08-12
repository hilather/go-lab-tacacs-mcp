package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHeaderRoundTripAndFamilies(t *testing.T) {
	t.Parallel()
	for _, typ := range []byte{TypeAuthen, TypeAuthor, TypeAcct} {
		in := Header{
			Version:   VersionByte(1),
			Type:      typ,
			SeqNo:     1,
			Flags:     FlagUnencrypted,
			SessionID: 0xaabbccdd,
			Length:    32,
		}
		got, err := DecodeHeader(in.Encode())
		if err != nil || got != in {
			t.Fatalf("type %d: got %#v err=%v", typ, got, err)
		}
	}
}

func TestHeaderTruncationAndHugeLength(t *testing.T) {
	t.Parallel()
	raw := make([]byte, HeaderSize)
	raw[0] = 0xc0
	for n := 0; n < HeaderSize; n++ {
		if _, err := DecodeHeader(raw[:n]); !errors.Is(err, ErrHeaderShort) {
			t.Fatalf("n=%d err=%v", n, err)
		}
	}
	raw[8], raw[9], raw[10], raw[11] = 0xff, 0xff, 0xff, 0xff
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.BodyBudget(0) != MaxBodyBytes {
		t.Fatalf("budget=%d", h.BodyBudget(0))
	}
	if _, body, err := DecodePacket(raw, 0); !errors.Is(err, ErrBodyTooLarge) || body != nil {
		t.Fatalf("decode packet err=%v body=%v", err, body)
	}
}

func TestUnknownTypeReplyFixture(t *testing.T) {
	t.Parallel()
	reqRaw, err := os.ReadFile(protocolFile(t, "fuzz", "header", "junk-unknown-type.bin"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(protocolFile(t, "header", "unknown-type-error-reply.bin"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeHeader(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := req.UnknownTypeReply()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply.Encode(), want) {
		t.Fatalf("got %x want %x", reply.Encode(), want)
	}
}

func TestUnknownFlagsAndValidate(t *testing.T) {
	t.Parallel()
	h, err := DecodeHeader([]byte{0x00, TypeAuthen, 0, 0xff, 0, 0, 0, 1, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); !errors.Is(err, ErrUnsupportedMajor) {
		t.Fatalf("major: %v", err)
	}
	h.Version = 0xc0
	if err := h.Validate(); !errors.Is(err, ErrSeqZero) {
		t.Fatalf("seq: %v", err)
	}
	cleared := h.ClearUnknownFlags()
	if cleared.Flags != (FlagUnencrypted | FlagSingleConnect) {
		t.Fatalf("flags=%#x", cleared.Flags)
	}
}

func TestHeaderSeeds(t *testing.T) {
	t.Parallel()
	dir := protocolFile(t, "fuzz", "header")
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
		if e.Name() == "truncated-11.bin" {
			if !errors.Is(err, ErrHeaderShort) {
				t.Fatalf("%s: %v", e.Name(), err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if !bytes.Equal(h.Encode(), raw[:HeaderSize]) {
			t.Fatalf("%s encode mismatch", e.Name())
		}
	}
	if n < 8 {
		t.Fatalf("seeds=%d", n)
	}
}

func TestHeaderCatalog(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "header", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		UnknownTypeReply struct {
			ReplyHex string `json:"reply_hex"`
		} `json:"unknown_type_reply"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	wire, err := hex.DecodeString(catalog.UnknownTypeReply.ReplyHex)
	if err != nil {
		t.Fatal(err)
	}
	h, err := DecodeHeader(wire)
	if err != nil || h.Length != 0 || h.SeqNo != 2 {
		t.Fatalf("reply %#v err=%v", h, err)
	}
}

func TestNextSeq(t *testing.T) {
	t.Parallel()
	if _, err := NextSeq(255); !errors.Is(err, ErrSeqWrap) {
		t.Fatalf("wrap: %v", err)
	}
	got, err := NextSeq(1)
	if err != nil || got != 2 {
		t.Fatalf("got %d %v", got, err)
	}
}

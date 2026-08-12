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

func TestDecodeEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	in := Header{
		Version:   VersionByte(0),
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

func TestDecodeHeaderTruncation(t *testing.T) {
	t.Parallel()
	raw := []byte{0xc0, TypeAuthen, 1, 0, 1, 2, 3, 4, 0, 0, 0, 0}
	for n := 0; n < HeaderSize; n++ {
		_, err := DecodeHeader(raw[:n])
		if !errors.Is(err, ErrHeaderShort) {
			t.Fatalf("n=%d err=%v", n, err)
		}
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
	if h.BodyBudget(0) != MaxBodyBytes {
		t.Fatalf("budget=%d", h.BodyBudget(0))
	}
	if _, err := h.AllocateBody(0); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("alloc: %v", err)
	}
}

func TestDecodePacketRejectsHugeLengthBeforeArithmetic(t *testing.T) {
	t.Parallel()
	// Length 0xffffffff would overflow HeaderSize+Length if added first.
	raw := []byte{0xc0, TypeAuthen, 1, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 'x'}
	h, body, err := DecodePacket(raw, 0)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if body != nil {
		t.Fatalf("body allocated: %d", len(body))
	}
	if h.Length != 0xffffffff {
		t.Fatalf("length=%d", h.Length)
	}
}

func TestBodyLengthBounds(t *testing.T) {
	t.Parallel()
	mk := func(n uint32) []byte {
		h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, Length: n}
		raw := h.Encode()
		if n <= 32 {
			return append(raw, bytes.Repeat([]byte{'a'}, int(n))...)
		}
		return raw
	}
	if _, body, err := DecodePacket(mk(0), 0); err != nil || len(body) != 0 {
		t.Fatalf("zero: body=%d err=%v", len(body), err)
	}
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, Length: MaxBodyBytes}
	if got := h.BodyBudget(0); got != MaxBodyBytes {
		t.Fatalf("max budget=%d", got)
	}
	if _, err := h.AllocateBody(0); err != nil {
		t.Fatalf("max alloc: %v", err)
	}
	h.Length = MaxBodyBytes + 1
	if _, err := h.AllocateBody(0); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("max+1: %v", err)
	}
	if h.BodyBudget(1024) != 1024 {
		t.Fatalf("custom budget=%d", h.BodyBudget(1024))
	}
}

func TestDecodePacketShortBody(t *testing.T) {
	t.Parallel()
	h := Header{Version: 0xc0, Type: TypeAcct, SeqNo: 1, Length: 4}
	_, _, err := DecodePacket(h.Encode(), 0)
	if !errors.Is(err, ErrBodyShort) {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodePacketExactBody(t *testing.T) {
	t.Parallel()
	body := []byte{9, 8, 7, 6}
	h := Header{Version: VersionByte(1), Type: TypeAuthor, SeqNo: 3, SessionID: 9, Length: uint32(len(body))}
	raw := append(append(h.Encode(), body...), 0xff)
	gotH, gotB, err := DecodePacket(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.Length = uint32(len(body))
	if gotH != h {
		t.Fatalf("header %#v want %#v", gotH, h)
	}
	if !bytes.Equal(gotB, body) {
		t.Fatalf("body %x", gotB)
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
	if h.KnownType() {
		t.Fatal("type 0x99 is unknown")
	}
	if err := h.Validate(); !errors.Is(err, ErrUnsupportedMajor) {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateSeqZero(t *testing.T) {
	t.Parallel()
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 0}
	if err := h.Validate(); !errors.Is(err, ErrSeqZero) {
		t.Fatalf("err=%v", err)
	}
}

func TestUnknownFlagsIgnoredOnReadZeroedOnWrite(t *testing.T) {
	t.Parallel()
	raw := []byte{0xc0, TypeAuthen, 1, 0x08 | FlagSingleConnect, 0, 0, 0, 5, 0, 0, 0, 0}
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Flags&0x08 == 0 {
		t.Fatal("unknown bit dropped on read")
	}
	cleared := h.ClearUnknownFlags()
	if cleared.Flags != FlagSingleConnect {
		t.Fatalf("flags=%#x", cleared.Flags)
	}
	enc := cleared.Encode()
	if enc[3] != FlagSingleConnect {
		t.Fatalf("encoded flags=%#x", enc[3])
	}
}

func TestUnknownTypeZeroBodyReply(t *testing.T) {
	t.Parallel()
	reqRaw, err := os.ReadFile(protocolFile(t, "fuzz", "header", "junk-unknown-type.bin"))
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, err := os.ReadFile(protocolFile(t, "header", "unknown-type-error-reply.bin"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeHeader(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	if req.KnownType() {
		t.Fatal("expected unknown type")
	}
	reply, err := req.UnknownTypeReply()
	if err != nil {
		t.Fatal(err)
	}
	if reply.SeqNo != req.SeqNo+1 || reply.Length != 0 {
		t.Fatalf("reply %#v", reply)
	}
	if reply.Version != req.Version || reply.Type != req.Type || reply.Flags != req.Flags || reply.SessionID != req.SessionID {
		t.Fatalf("header mutated: %#v vs %#v", reply, req)
	}
	if !bytes.Equal(reply.Encode(), wantRaw) {
		t.Fatalf("got %x want %x", reply.Encode(), wantRaw)
	}
}

func TestUnknownTypeReplySeqWrap(t *testing.T) {
	t.Parallel()
	h := Header{Version: 0xc0, Type: 0x99, SeqNo: 255, SessionID: 1}
	if _, err := h.UnknownTypeReply(); !errors.Is(err, ErrSeqWrap) {
		t.Fatalf("err=%v", err)
	}
}

func TestNextSeq(t *testing.T) {
	t.Parallel()
	got, err := NextSeq(1)
	if err != nil || got != 2 {
		t.Fatalf("NextSeq(1)=%d,%v", got, err)
	}
	if _, err := NextSeq(0); !errors.Is(err, ErrSeqZero) {
		t.Fatalf("zero: %v", err)
	}
	if _, err := NextSeq(255); !errors.Is(err, ErrSeqWrap) {
		t.Fatalf("wrap: %v", err)
	}
}

func TestHeaderSeedsFromTestdata(t *testing.T) {
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
		switch e.Name() {
		case "truncated-11.bin":
			if !errors.Is(err, ErrHeaderShort) {
				t.Fatalf("%s: err=%v", e.Name(), err)
			}
		default:
			if err != nil {
				t.Fatalf("%s: %v", e.Name(), err)
			}
			if e.Name() == "junk-huge-length.bin" && h.BodyBudget(0) != MaxBodyBytes {
				t.Fatalf("%s budget=%d", e.Name(), h.BodyBudget(0))
			}
			if e.Name() == "seq-zero.bin" && !errors.Is(h.Validate(), ErrSeqZero) {
				t.Fatalf("%s validate=%v", e.Name(), h.Validate())
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

func TestHeaderCatalogVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(protocolFile(t, "header", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Seeds []struct {
			Name   string `json:"name"`
			RawHex string `json:"raw_hex"`
			Len    int    `json:"len"`
			Header *struct {
				Version   byte   `json:"version"`
				Type      byte   `json:"type"`
				SeqNo     byte   `json:"seq_no"`
				Flags     byte   `json:"flags"`
				SessionID uint32 `json:"session_id"`
				Length    uint32 `json:"length"`
			} `json:"header"`
		} `json:"seeds"`
		UnknownTypeReply struct {
			ReplyHex string `json:"reply_hex"`
		} `json:"unknown_type_reply"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Seeds) < 8 {
		t.Fatalf("catalog seeds=%d", len(catalog.Seeds))
	}
	for _, s := range catalog.Seeds {
		wire, err := hex.DecodeString(s.RawHex)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if len(wire) != s.Len {
			t.Fatalf("%s len %d vs %d", s.Name, len(wire), s.Len)
		}
		h, err := DecodeHeader(wire)
		if s.Len < HeaderSize {
			if !errors.Is(err, ErrHeaderShort) {
				t.Fatalf("%s: %v", s.Name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if s.Header == nil {
			t.Fatalf("%s missing decoded fields", s.Name)
		}
		want := Header{
			Version:   s.Header.Version,
			Type:      s.Header.Type,
			SeqNo:     s.Header.SeqNo,
			Flags:     s.Header.Flags,
			SessionID: s.Header.SessionID,
			Length:    s.Header.Length,
		}
		if h != want {
			t.Fatalf("%s got %#v want %#v", s.Name, h, want)
		}
	}
	reply, err := hex.DecodeString(catalog.UnknownTypeReply.ReplyHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != HeaderSize {
		t.Fatalf("reply len %d", len(reply))
	}
}

func TestKnownTypes(t *testing.T) {
	t.Parallel()
	for _, typ := range []byte{TypeAuthen, TypeAuthor, TypeAcct} {
		h := Header{Type: typ}
		if !h.KnownType() {
			t.Fatalf("type %d should be known", typ)
		}
	}
	if (Header{Type: 0}).KnownType() {
		t.Fatal("type 0 is unknown")
	}
}

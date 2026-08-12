package codec

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func FuzzHeader(f *testing.F) {
	dir := protocolFile(f, "fuzz", "header")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte{})
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := DecodeHeader(data)
		if err != nil {
			return
		}
		enc := h.Encode()
		if len(enc) != HeaderSize {
			t.Fatalf("encode len %d", len(enc))
		}
		got, err := DecodeHeader(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != h {
			t.Fatalf("round-trip %#v vs %#v", got, h)
		}
		_ = h.BodyBudget(0)
		if _, err := h.AllocateBody(0); err == nil && h.Length > MaxBodyBytes {
			t.Fatalf("allocated over budget length=%d", h.Length)
		}
	})
}

func FuzzObfuscate(f *testing.F) {
	f.Add(uint32(1), byte(0xc0), byte(1), []byte("key"), []byte("body"))
	f.Add(uint32(0), byte(0), byte(0), []byte{}, []byte{})
	f.Add(uint32(0x01020304), byte(0xc0), byte(1), []byte("lab-test-shared-secret"), make([]byte, 17))
	f.Fuzz(func(t *testing.T, sessionID uint32, version, seq byte, key, body []byte) {
		once := Obfuscate(sessionID, version, seq, key, body)
		twice := Obfuscate(sessionID, version, seq, key, once)
		want := body
		if want == nil {
			want = []byte{}
		}
		if len(twice) != len(want) {
			t.Fatalf("len %d vs %d", len(twice), len(want))
		}
		for i := range twice {
			if twice[i] != want[i] {
				t.Fatalf("round-trip mismatch at %d", i)
			}
		}
	})
}

func FuzzDecodePacket(f *testing.F) {
	h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
	f.Add(append(h.Encode(), 1, 2, 3, 4), uint32(MaxBodyBytes))
	f.Add(make([]byte, 12), uint32(0))
	huge := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: 1, Length: 0xffffffff}
	f.Add(huge.Encode(), uint32(0))
	f.Fuzz(func(t *testing.T, data []byte, max uint32) {
		_, body, err := DecodePacket(data, max)
		if err != nil {
			if body != nil {
				t.Fatalf("body set on error: %d", len(body))
			}
			return
		}
		cap := ClampMaxBody(max)
		if uint32(len(body)) > cap {
			t.Fatalf("body %d > cap %d", len(body), cap)
		}
	})
}

func addBodySeeds(f *testing.F) {
	f.Helper()
	dir := protocolFile(f, "fuzz", "bodies")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
}

func FuzzAuthenStart(f *testing.F) {
	addBodySeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := DecodeAuthenStart(data)
		if err != nil {
			return
		}
		enc, err := st.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeAuthenStart(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got.Action != st.Action || got.Type != st.Type || got.Service != st.Service {
			t.Fatalf("round-trip %#v vs %#v", got, st)
		}
		_, _ = ClassifyAuthenStart(0, st)
		_, _ = ClassifyAuthenStart(1, st)
	})
}

func FuzzAuthorRequest(f *testing.F) {
	addBodySeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := DecodeAuthorRequest(data)
		if err != nil {
			return
		}
		enc, err := req.Encode()
		if err != nil {
			return
		}
		if uint32(len(enc)) > MaxBodyBytes {
			t.Fatalf("encoded %d", len(enc))
		}
	})
}

func FuzzAcctRequest(f *testing.F) {
	addBodySeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := DecodeAcctRequest(data)
		if err != nil && !errors.Is(err, ErrAcctFlags) {
			return
		}
		if err == nil && !ValidAcctFlags(req.Flags) {
			t.Fatalf("accepted flags %#x", req.Flags)
		}
	})
}

func FuzzSequence(f *testing.F) {
	dir := protocolFile(f, "fuzz", "sequence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte{1, 3, 5})
	f.Add([]byte{0, 2, 255})
	f.Fuzz(func(t *testing.T, seqs []byte) {
		s := NewSequence(1, TypeAuthen)
		for _, seq := range seqs {
			h := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: seq, SessionID: 1}
			if err := s.CheckRequest(h); err != nil {
				if s.Closed() {
					return
				}
				continue
			}
			if !ClientSeq(seq) {
				t.Fatalf("accepted even or zero seq %d", seq)
			}
			if _, err := s.NextReply(0); err != nil {
				return
			}
		}
	})
}

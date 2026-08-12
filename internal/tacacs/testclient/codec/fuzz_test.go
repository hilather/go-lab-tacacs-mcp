package codec

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzReadStart(f *testing.F) {
	dir := protocolFile(f, "fuzz", "bodies")
	ents, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := ReadStart(data)
		if err != nil {
			return
		}
		enc, err := WriteStart(st)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStart(enc); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzWalk(f *testing.F) {
	dir := protocolFile(f, "fuzz", "sequence")
	ents, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, seqs []byte) {
		w := NewWalk(1, TypeAuthen)
		for range seqs {
			h, err := w.Out(0)
			if err != nil {
				return
			}
			if !OddSeq(h.SeqNo) {
				t.Fatalf("even client seq %d", h.SeqNo)
			}
			reply := Header{Version: 0xc0, Type: TypeAuthen, SeqNo: h.SeqNo + 1, SessionID: 1}
			if reply.SeqNo == 0 {
				return
			}
			if err := w.In(reply); err != nil {
				return
			}
		}
	})
}

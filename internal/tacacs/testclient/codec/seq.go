package codec

import "io"

func OddSeq(seq byte) bool  { return seq&1 == 1 }
func EvenSeq(seq byte) bool { return seq != 0 && seq&1 == 0 }

// Walk is the client-side session stepper (odd send, even expect).
type Walk struct {
	id    uint32
	kind  byte
	want  byte
	live  bool
	got   bool
	dead  bool
	n     int
	limit int
}

func NewWalk(id uint32, kind byte) *Walk {
	return &Walk{id: id, kind: kind, want: 1, limit: 32}
}

func (w *Walk) Out(flags byte) (Header, error) {
	if w.dead {
		return Header{}, ErrClosed
	}
	if !OddSeq(w.want) {
		return Header{}, ErrParity
	}
	if w.live && !w.got {
		return Header{}, ErrEarly
	}
	if (w.kind == TypeAuthor || w.kind == TypeAcct) && w.got {
		w.dead = true
		return Header{}, ErrClosed
	}
	if w.live {
		w.n++
		if w.n > w.limit {
			w.dead = true
			return Header{}, ErrRounds
		}
	}
	seq := w.want
	next, err := NextSeq(seq)
	if err != nil {
		w.dead = true
		return Header{}, err
	}
	w.want = next
	w.live = true
	return Header{Type: w.kind, SeqNo: seq, Flags: flags, SessionID: w.id}, nil
}

func (w *Walk) In(h Header) error {
	if w.dead {
		return ErrClosed
	}
	if h.SessionID != w.id || h.Type != w.kind {
		return ErrMismatch
	}
	if err := h.Validate(); err != nil {
		return err
	}
	if !EvenSeq(h.SeqNo) {
		return ErrParity
	}
	if h.SeqNo != w.want {
		return ErrOrder
	}
	next, err := NextSeq(h.SeqNo)
	if err != nil {
		w.dead = true
		return err
	}
	w.want = next
	w.got = true
	if w.kind == TypeAuthor || w.kind == TypeAcct {
		w.dead = true
	}
	return nil
}

func (w *Walk) Done() bool { return w.dead }

// Mux records single-connect on the first pair only.
type Mux struct {
	a, b, ok, fin bool
}

func (m *Mux) Offer(flags byte) {
	if m.a || m.fin {
		return
	}
	m.a = true
	m.b = flags&FlagSingleConnect != 0
}

func (m *Mux) Answer(flags byte) bool {
	if m.fin {
		return m.ok
	}
	m.ok = m.a && m.b && flags&FlagSingleConnect != 0
	m.fin = true
	return m.ok
}

func (m *Mux) Ready() bool { return m.ok }

func (m *Mux) Guard() error {
	if m.a && !m.fin {
		return ErrEarly
	}
	return nil
}

func FirstPairSingle(first bool, c, s byte) bool {
	return first && c&FlagSingleConnect != 0 && s&FlagSingleConnect != 0
}

func GenerateSessionID(src io.Reader) (uint32, error) {
	if src == nil {
		return 0, ErrRand
	}
	var b [4]byte
	n, err := src.Read(b[:])
	if err != nil || n != 4 {
		return 0, ErrRand
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

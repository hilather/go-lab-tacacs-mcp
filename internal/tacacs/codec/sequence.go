package codec

// ClientSeq reports whether seq is a client-originated (odd) sequence.
func ClientSeq(seq byte) bool { return seq%2 == 1 }

// ServerSeq reports whether seq is a server-originated (even, non-zero) sequence.
func ServerSeq(seq byte) bool { return seq != 0 && seq%2 == 0 }

// Sequence is the per-session packet-order machine (RFC 8907 §4.2).
// Client packets are odd; server packets are even; sequence 256 is never used.
type Sequence struct {
	sessionID uint32
	typ       byte
	next      byte
	started   bool
	replied   bool
	closed    bool
	continues int
	maxCont   int
	wrap      bool
}

// NewSequence starts a session that expects client sequence 1.
func NewSequence(sessionID uint32, typ byte) *Sequence {
	return &Sequence{
		sessionID: sessionID,
		typ:       typ,
		next:      1,
		maxCont:   DefaultMaxContinues,
	}
}

// SetMaxContinues overrides the ASCII CONTINUE cap. 0 means DefaultMaxContinues.
func (s *Sequence) SetMaxContinues(n int) {
	if n <= 0 {
		n = DefaultMaxContinues
	}
	s.maxCont = n
}

// CheckRequest validates a client header against the expected next sequence.
func (s *Sequence) CheckRequest(h Header) error {
	if s.closed {
		return ErrSessionClosed
	}
	if h.SessionID != s.sessionID || h.Type != s.typ {
		return ErrSessionMismatch
	}
	if err := h.Validate(); err != nil {
		return err
	}
	if !ClientSeq(h.SeqNo) {
		return ErrSeqParity
	}
	if s.started && !s.replied {
		return ErrPrematurePacket
	}
	if h.SeqNo != s.next {
		return ErrSeqUnexpected
	}
	if !s.started {
		if h.SeqNo != 1 {
			return ErrSeqUnexpected
		}
		s.started = true
	} else {
		if s.typ == TypeAuthor || s.typ == TypeAcct {
			s.closed = true
			return ErrSessionClosed
		}
		s.continues++
		if s.continues > s.maxCont {
			s.closed = true
			return ErrTooManyContinues
		}
	}
	next, err := NextSeq(h.SeqNo)
	if err != nil {
		// 255 is a legal client packet; the following increment is not.
		s.wrap = true
		return nil
	}
	s.next = next
	return nil
}

// NextReply allocates the next even sequence for a server packet.
func (s *Sequence) NextReply(flags byte) (Header, error) {
	if s.closed {
		return Header{}, ErrSessionClosed
	}
	if !s.started {
		return Header{}, ErrSeqUnexpected
	}
	if s.wrap {
		s.closed = true
		return Header{}, ErrSeqWrap
	}
	if !ServerSeq(s.next) {
		return Header{}, ErrSeqParity
	}
	seq := s.next
	next, err := NextSeq(seq)
	if err != nil {
		s.closed = true
		return Header{}, err
	}
	s.next = next
	s.replied = true
	if s.typ == TypeAuthor || s.typ == TypeAcct {
		s.closed = true
	}
	return Header{
		Type:      s.typ,
		SeqNo:     seq,
		Flags:     flags,
		SessionID: s.sessionID,
	}, nil
}

// Closed reports whether the session has terminated (wrap, limit, or author/acct done).
func (s *Sequence) Closed() bool { return s.closed }

// Close terminates the session.
func (s *Sequence) Close() { s.closed = true }

// Next reports the next expected sequence number.
func (s *Sequence) Next() byte { return s.next }

// SingleConnect is the connection-level multiplexing negotiation (RFC 8907 §4.3).
// The flag is consulted only on the first request/reply pair.
type SingleConnect struct {
	sawClient bool
	client    bool
	done      bool
	ok        bool
}

// OnClientFirst records the client's first-packet flag. Later packets are ignored.
func (s *SingleConnect) OnClientFirst(flags byte) {
	if s.sawClient || s.done {
		return
	}
	s.sawClient = true
	s.client = flags&FlagSingleConnect != 0
}

// OnServerFirst records the server's first-reply flag and returns the result.
func (s *SingleConnect) OnServerFirst(flags byte) bool {
	if s.done {
		return s.ok
	}
	s.ok = s.sawClient && s.client && flags&FlagSingleConnect != 0
	s.done = true
	return s.ok
}

// Negotiated reports whether both sides set the flag on the first pair.
func (s *SingleConnect) Negotiated() bool { return s.ok }

// Pending reports that a first request was seen and the first reply has not.
func (s *SingleConnect) Pending() bool { return s.sawClient && !s.done }

// AllowNewSession rejects a second session while the first pair is incomplete.
func (s *SingleConnect) AllowNewSession() error {
	if s.Pending() {
		return ErrPrematurePacket
	}
	return nil
}

// NegotiateSingleConnect is true only when both sides set the flag on the first pair.
func NegotiateSingleConnect(firstPair bool, clientFlags, serverFlags byte) bool {
	if !firstPair {
		return false
	}
	return clientFlags&FlagSingleConnect != 0 && serverFlags&FlagSingleConnect != 0
}

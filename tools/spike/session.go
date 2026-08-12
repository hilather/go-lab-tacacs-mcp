package spike

// NextSeq returns seq+1. Sequence numbers never wrap (RFC 8907 §4.2).
func NextSeq(seq byte) (byte, error) {
	if seq == 0 {
		return 0, ErrSeqZero
	}
	if seq == 255 {
		return 0, ErrSeqWrap
	}
	return seq + 1, nil
}

// ClientSeq reports whether seq is a client-originated (odd) sequence.
func ClientSeq(seq byte) bool { return seq%2 == 1 }

// ServerSeq reports whether seq is a server-originated (even, non-zero) sequence.
func ServerSeq(seq byte) bool { return seq != 0 && seq%2 == 0 }

// NegotiateSingleConnect is true only when both sides set the flag on the
// first request/reply pair. Callers must ignore the flag afterward.
func NegotiateSingleConnect(firstPair bool, clientFlags, serverFlags byte) bool {
	if !firstPair {
		return false
	}
	return clientFlags&FlagSingleConnect != 0 && serverFlags&FlagSingleConnect != 0
}

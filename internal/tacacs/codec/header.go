package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RFC 8907 §4.1 header layout and recommended body cap.
const (
	HeaderSize = 12

	MajorVer = 0x0c

	TypeAuthen = 0x01
	TypeAuthor = 0x02
	TypeAcct   = 0x03

	FlagUnencrypted   = 0x01
	FlagSingleConnect = 0x04
	FlagKnownMask     = FlagUnencrypted | FlagSingleConnect

	// MaxBodyBytes is the RFC recommended maximum packet body (2^16).
	// DecodeHeader records Length but never allocates a body of this size.
	MaxBodyBytes = 65536
)

var (
	ErrHeaderShort      = errors.New("tacacs header shorter than 12 bytes")
	ErrUnsupportedMajor = errors.New("tacacs major version is not 0xc")
	ErrUnknownType      = errors.New("tacacs packet type is not authen, author, or acct")
	ErrSeqZero          = errors.New("tacacs sequence number 0 is invalid")
	ErrSeqWrap          = errors.New("tacacs sequence would wrap past 255")
	ErrBodyTooLarge     = errors.New("tacacs body length exceeds budget")
	ErrBodyShort        = errors.New("tacacs body shorter than header length")
)

// Header is the 12-byte TACACS+ common header (RFC 8907 §4.1).
type Header struct {
	Version   byte
	Type      byte
	SeqNo     byte
	Flags     byte
	SessionID uint32
	Length    uint32
}

// VersionByte builds a version octet with major 0xc and the given minor nibble.
func VersionByte(minor byte) byte {
	return MajorVer<<4 | (minor & 0x0f)
}

// Major returns the high nibble of Version.
func (h Header) Major() byte { return h.Version >> 4 }

// Minor returns the low nibble of Version.
func (h Header) Minor() byte { return h.Version & 0x0f }

// KnownType reports whether Type is AUTHEN, AUTHOR, or ACCT.
func (h Header) KnownType() bool {
	switch h.Type {
	case TypeAuthen, TypeAuthor, TypeAcct:
		return true
	default:
		return false
	}
}

// DecodeHeader parses a TACACS+ header from the first 12 bytes of p.
// Extra trailing bytes are ignored. Length is recorded only; this
// function never allocates a packet body.
func DecodeHeader(p []byte) (Header, error) {
	if len(p) < HeaderSize {
		return Header{}, fmt.Errorf("%w: got %d", ErrHeaderShort, len(p))
	}
	return Header{
		Version:   p[0],
		Type:      p[1],
		SeqNo:     p[2],
		Flags:     p[3],
		SessionID: binary.BigEndian.Uint32(p[4:8]),
		Length:    binary.BigEndian.Uint32(p[8:12]),
	}, nil
}

// Encode writes the 12-byte wire form. Stored flags are written as-is
// so a decode/encode round-trip is lossless; call ClearUnknownFlags
// before originating a packet (RFC 8907 unknown bits are zero on write).
func (h Header) Encode() []byte {
	out := make([]byte, HeaderSize)
	out[0] = h.Version
	out[1] = h.Type
	out[2] = h.SeqNo
	out[3] = h.Flags
	binary.BigEndian.PutUint32(out[4:8], h.SessionID)
	binary.BigEndian.PutUint32(out[8:12], h.Length)
	return out
}

// ClearUnknownFlags returns a copy with only defined flag bits retained.
func (h Header) ClearUnknownFlags() Header {
	h.Flags &= FlagKnownMask
	return h
}

// Validate reports unsupported major version and sequence 0.
// Unknown Type is not an error here; callers send UnknownTypeReply instead.
func (h Header) Validate() error {
	if h.Major() != MajorVer {
		return ErrUnsupportedMajor
	}
	if h.SeqNo == 0 {
		return ErrSeqZero
	}
	return nil
}

// ClampMaxBody returns max, or MaxBodyBytes when max is 0 or larger
// than the RFC recommended cap.
func ClampMaxBody(max uint32) uint32 {
	if max == 0 || max > MaxBodyBytes {
		return MaxBodyBytes
	}
	return max
}

// BodyBudget is how many body bytes a reader may request after this header.
// It never exceeds the configured cap (default MaxBodyBytes), even when
// Length is 0xffffffff.
func (h Header) BodyBudget(max uint32) uint32 {
	max = ClampMaxBody(max)
	if h.Length > max {
		return max
	}
	return h.Length
}

// AllocateBody returns a buffer of h.Length bytes, or an error if Length
// exceeds the budget. It never allocates the claimed Length when that
// value is above the cap.
func (h Header) AllocateBody(max uint32) ([]byte, error) {
	max = ClampMaxBody(max)
	if h.Length > max {
		return nil, fmt.Errorf("%w: length=%d max=%d", ErrBodyTooLarge, h.Length, max)
	}
	if h.Length == 0 {
		return []byte{}, nil
	}
	return make([]byte, h.Length), nil
}

// DecodePacket parses a header plus a body of exactly header.Length bytes.
// A Length above the budget is rejected before any body allocation or
// HeaderSize+Length arithmetic.
func DecodePacket(p []byte, max uint32) (Header, []byte, error) {
	h, err := DecodeHeader(p)
	if err != nil {
		return Header{}, nil, err
	}
	body, err := h.AllocateBody(max)
	if err != nil {
		return h, nil, err
	}
	need := HeaderSize + int(h.Length)
	if len(p) < need {
		have := 0
		if len(p) > HeaderSize {
			have = len(p) - HeaderSize
		}
		return h, nil, fmt.Errorf("%w: have %d want %d", ErrBodyShort, have, h.Length)
	}
	copy(body, p[HeaderSize:need])
	return h, body, nil
}

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

// UnknownTypeReply is the RFC 8907 §3.6 error header used when the
// incoming type cannot be determined: identical header, seq+1, length 0.
func (h Header) UnknownTypeReply() (Header, error) {
	seq, err := NextSeq(h.SeqNo)
	if err != nil {
		return Header{}, err
	}
	h.SeqNo = seq
	h.Length = 0
	return h, nil
}

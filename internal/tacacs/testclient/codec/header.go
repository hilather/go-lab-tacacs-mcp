package codec

import (
	"errors"
	"fmt"
)

// RFC 8907 §4.1 common header.
const (
	HeaderSize = 12

	MajorVer = 0x0c

	TypeAuthen = 0x01
	TypeAuthor = 0x02
	TypeAcct   = 0x03

	FlagUnencrypted   = 0x01
	FlagSingleConnect = 0x04
	FlagKnownMask     = FlagUnencrypted | FlagSingleConnect

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
func VersionByte(minor byte) byte { return MajorVer<<4 | minor&0x0f }

func (h Header) Major() byte { return h.Version >> 4 }
func (h Header) Minor() byte { return h.Version & 0x0f }

func (h Header) KnownType() bool {
	return h.Type == TypeAuthen || h.Type == TypeAuthor || h.Type == TypeAcct
}

func getUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// DecodeHeader reads the first 12 bytes. It never allocates a body from Length.
func DecodeHeader(p []byte) (Header, error) {
	if len(p) < HeaderSize {
		return Header{}, fmt.Errorf("%w: got %d", ErrHeaderShort, len(p))
	}
	return Header{
		Version:   p[0],
		Type:      p[1],
		SeqNo:     p[2],
		Flags:     p[3],
		SessionID: getUint32(p[4:8]),
		Length:    getUint32(p[8:12]),
	}, nil
}

// Encode serializes the header. Flags are written as stored; use
// ClearUnknownFlags when originating a packet.
func (h Header) Encode() []byte {
	var out [HeaderSize]byte
	out[0] = h.Version
	out[1] = h.Type
	out[2] = h.SeqNo
	out[3] = h.Flags
	putUint32(out[4:8], h.SessionID)
	putUint32(out[8:12], h.Length)
	return out[:]
}

func (h Header) ClearUnknownFlags() Header {
	h.Flags &= FlagKnownMask
	return h
}

func (h Header) Validate() error {
	if h.Major() != MajorVer {
		return ErrUnsupportedMajor
	}
	if h.SeqNo == 0 {
		return ErrSeqZero
	}
	return nil
}

func ClampMaxBody(max uint32) uint32 {
	if max == 0 || max > MaxBodyBytes {
		return MaxBodyBytes
	}
	return max
}

func (h Header) BodyBudget(max uint32) uint32 {
	max = ClampMaxBody(max)
	if h.Length < max {
		return h.Length
	}
	return max
}

func (h Header) AllocateBody(max uint32) ([]byte, error) {
	max = ClampMaxBody(max)
	if h.Length > max {
		return nil, fmt.Errorf("%w: length=%d max=%d", ErrBodyTooLarge, h.Length, max)
	}
	buf := make([]byte, int(h.Length))
	return buf, nil
}

// DecodePacket rejects Length above the budget before adding HeaderSize+Length.
func DecodePacket(p []byte, max uint32) (Header, []byte, error) {
	h, err := DecodeHeader(p)
	if err != nil {
		return Header{}, nil, err
	}
	body, err := h.AllocateBody(max)
	if err != nil {
		return h, nil, err
	}
	// Length is <= MaxBodyBytes after AllocateBody, so this add cannot overflow int.
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

func NextSeq(seq byte) (byte, error) {
	switch seq {
	case 0:
		return 0, ErrSeqZero
	case 255:
		return 0, ErrSeqWrap
	default:
		return seq + 1, nil
	}
}

// UnknownTypeReply is RFC 8907 §3.6: identical header, seq+1, length 0.
func (h Header) UnknownTypeReply() (Header, error) {
	next, err := NextSeq(h.SeqNo)
	if err != nil {
		return Header{}, err
	}
	return Header{
		Version:   h.Version,
		Type:      h.Type,
		SeqNo:     next,
		Flags:     h.Flags,
		SessionID: h.SessionID,
		Length:    0,
	}, nil
}

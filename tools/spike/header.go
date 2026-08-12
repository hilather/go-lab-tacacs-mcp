package spike

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

	// MaxBodyBytes is the RFC recommended maximum packet body (2^16).
	// DecodeHeader records Length but never allocates a body of this size.
	MaxBodyBytes = 65536
)

var (
	ErrHeaderShort = errors.New("tacacs header shorter than 12 bytes")
	ErrSeqZero     = errors.New("tacacs sequence number 0 is invalid")
	ErrSeqWrap     = errors.New("tacacs sequence would wrap past 255")
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

// Major returns the high nibble of Version.
func (h Header) Major() byte { return h.Version >> 4 }

// Minor returns the low nibble of Version.
func (h Header) Minor() byte { return h.Version & 0x0f }

// DecodeHeader parses a TACACS+ header from the first 12 bytes of p.
// Extra trailing bytes are ignored. Length is recorded only; this function
// never allocates a packet body.
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

// Encode writes the 12-byte wire form.
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

// BodyBudget is how many body bytes a reader may request after this header.
// It never exceeds MaxBodyBytes, even when Length is 0xffffffff.
func (h Header) BodyBudget() uint32 {
	if h.Length > MaxBodyBytes {
		return MaxBodyBytes
	}
	return h.Length
}

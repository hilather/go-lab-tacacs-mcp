// Package peap implements outer PEAP (EAP type 25) and TLS-in-EAP framing.
// Inner EAP methods are not interpreted.
package peap

import (
	"encoding/binary"
	"errors"
)

// Type is EAP type PEAP (25).
const Type byte = 25

// RFC 5216 TLS-in-EAP flags. Version occupies the low 3 bits.
const (
	FlagLength  byte = 0x80
	FlagMore    byte = 0x40
	FlagStart   byte = 0x20
	VersionMask byte = 0x07
	Version0    byte = 0
)

// Payload is one TLS-in-EAP PEAP body (flags + optional length + TLS data).
type Payload struct {
	LengthIncluded bool
	MoreFragments  bool
	Start          bool
	Version        uint8
	TLSMessageLen  uint32
	TLSData        []byte
}

// EncodeStart returns the PEAPv0 Start body (S flag, no TLS data).
func EncodeStart() []byte {
	return Encode(Payload{Start: true, Version: Version0})
}

// Parse decodes a TLS-in-EAP PEAP body.
func Parse(data []byte) (Payload, error) {
	if len(data) < 1 {
		return Payload{}, errors.New("peap: empty TLS-in-EAP payload")
	}
	flags := data[0]
	p := Payload{
		LengthIncluded: flags&FlagLength != 0,
		MoreFragments:  flags&FlagMore != 0,
		Start:          flags&FlagStart != 0,
		Version:        flags & VersionMask,
	}
	rest := data[1:]
	if p.LengthIncluded {
		if len(rest) < 4 {
			return Payload{}, errors.New("peap: L flag without TLS length")
		}
		p.TLSMessageLen = binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
	}
	if len(rest) > 0 {
		p.TLSData = append([]byte(nil), rest...)
	}
	return p, nil
}

// Encode writes flags, optional TLS message length, and TLS data.
func Encode(p Payload) []byte {
	flags := p.Version & VersionMask
	if p.LengthIncluded {
		flags |= FlagLength
	}
	if p.MoreFragments {
		flags |= FlagMore
	}
	if p.Start {
		flags |= FlagStart
	}
	if p.LengthIncluded {
		out := make([]byte, 5+len(p.TLSData))
		out[0] = flags
		binary.BigEndian.PutUint32(out[1:5], p.TLSMessageLen)
		copy(out[5:], p.TLSData)
		return out
	}
	out := make([]byte, 1+len(p.TLSData))
	out[0] = flags
	copy(out[1:], p.TLSData)
	return out
}

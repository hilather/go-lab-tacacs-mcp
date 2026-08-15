package codec

import (
	"encoding/binary"
	"fmt"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

// Encode writes a packet with a canonical Length using DefaultBounds.
func Encode(p Packet) ([]byte, error) {
	return EncodeBounded(p, DefaultBounds())
}

// EncodeBounded writes Code, Identifier, canonical Length, Authenticator,
// and attributes. It fails before write if the result exceeds the cap.
func EncodeBounded(p Packet, b Bounds) ([]byte, error) {
	b = b.normalized()
	if p.Attributes.Len() > b.MaxAttributes {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManyAttributes, p.Attributes.Len(), b.MaxAttributes)
	}
	if p.Attributes.ValueBytes() > b.MaxValueBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrAttributeBudget, p.Attributes.ValueBytes(), b.MaxValueBytes)
	}
	payload, err := attribute.Encode(p.Attributes)
	if err != nil {
		return nil, err
	}
	n := HeaderSize + len(payload)
	if n > b.MaxPacketBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrPacketTooLarge, n, b.MaxPacketBytes)
	}
	out := make([]byte, n)
	out[0] = byte(p.Code)
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(n))
	copy(out[4:HeaderSize], p.Authenticator[:])
	copy(out[HeaderSize:], payload)
	return out, nil
}

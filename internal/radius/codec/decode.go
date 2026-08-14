package codec

import (
	"encoding/binary"
	"fmt"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

// DecodeHeader parses the first 20 octets. Extra trailing bytes are ignored.
// Length is recorded only; this function never walks attributes.
func DecodeHeader(p []byte) (Header, error) {
	if len(p) < HeaderSize {
		return Header{}, fmt.Errorf("%w: got %d", ErrHeaderShort, len(p))
	}
	var h Header
	h.Code = Code(p[0])
	h.Identifier = p[1]
	h.Length = binary.BigEndian.Uint16(p[2:4])
	copy(h.Authenticator[:], p[4:HeaderSize])
	return h, nil
}

// Decode parses one datagram using DefaultBounds.
func Decode(datagram []byte) (Packet, error) {
	return DecodeBounded(datagram, DefaultBounds())
}

// DecodeBounded parses one datagram. It never stitches reads. Declared
// length must be >= 20, <= max, and <= the datagram. Bytes past Length
// are padding. Attribute overflow discards the packet.
func DecodeBounded(datagram []byte, b Bounds) (Packet, error) {
	h, err := DecodeHeader(datagram)
	if err != nil {
		return Packet{}, err
	}
	b = b.normalized()
	declared := int(h.Length)
	if declared < MinPacketBytes {
		return Packet{}, fmt.Errorf("%w: declared %d", ErrInvalidLength, declared)
	}
	if declared > b.MaxPacketBytes {
		return Packet{}, fmt.Errorf("%w: declared %d max %d", ErrInvalidLength, declared, b.MaxPacketBytes)
	}
	if declared > len(datagram) {
		return Packet{}, fmt.Errorf("%w: declared %d datagram %d", ErrInvalidLength, declared, len(datagram))
	}
	attrs, err := attribute.Decode(datagram[HeaderSize:declared], b.MaxAttributes, b.MaxValueBytes)
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		Code:          h.Code,
		Identifier:    h.Identifier,
		Authenticator: h.Authenticator,
		Attributes:    attrs,
	}, nil
}

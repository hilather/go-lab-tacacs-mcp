package codec

import "fmt"

// Encode writes Code, Identifier, canonical Length, Authenticator, and attrs.
func Encode(p Packet) ([]byte, error) {
	return EncodeLimited(p, MaxPacket, MaxAttrs, MaxValues)
}

// EncodeLimited fails before write if the result exceeds the caps.
func EncodeLimited(p Packet, maxPacket, maxAttrs, maxValueBytes int) ([]byte, error) {
	if maxPacket <= 0 || maxPacket > MaxPacket {
		maxPacket = MaxPacket
	}
	if maxAttrs <= 0 {
		maxAttrs = MaxAttrs
	}
	if maxValueBytes <= 0 {
		maxValueBytes = MaxValues
	}
	if len(p.Attrs) > maxAttrs {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManyAttrs, len(p.Attrs), maxAttrs)
	}
	if valueBytes(p.Attrs) > maxValueBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrAttrBudget, valueBytes(p.Attrs), maxValueBytes)
	}
	payload, err := encodeAttrs(p.Attrs)
	if err != nil {
		return nil, err
	}
	n := HeaderLen + len(payload)
	if n > maxPacket {
		return nil, fmt.Errorf("%w: %d > %d", ErrPacketTooBig, n, maxPacket)
	}
	out := make([]byte, n)
	out[0] = byte(p.Code)
	out[1] = p.Identifier
	put16(out[2:4], uint16(n))
	copy(out[4:HeaderLen], p.Authenticator[:])
	copy(out[HeaderLen:], payload)
	return out, nil
}

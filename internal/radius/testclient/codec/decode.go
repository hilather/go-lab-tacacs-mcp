package codec

import "fmt"

// DecodeHeader reads the first 20 octets. Extra trailing bytes are ignored.
func DecodeHeader(p []byte) (Header, error) {
	if len(p) < HeaderLen {
		return Header{}, fmt.Errorf("%w: got %d", ErrHeaderShort, len(p))
	}
	var h Header
	h.Code = Code(p[0])
	h.Identifier = p[1]
	h.Length = be16(p[2:4])
	copy(h.Authenticator[:], p[4:HeaderLen])
	return h, nil
}

// Decode parses one datagram. It never stitches reads. Declared length
// must be 20..4096 and ≤ the datagram. Bytes past Length are padding.
func Decode(datagram []byte) (Packet, error) {
	return DecodeLimited(datagram, MaxPacket, MaxAttrs, MaxValues)
}

// DecodeLimited is Decode with caller caps. Zero caps mean the defaults.
func DecodeLimited(datagram []byte, maxPacket, maxAttrs, maxValueBytes int) (Packet, error) {
	h, err := DecodeHeader(datagram)
	if err != nil {
		return Packet{}, err
	}
	if maxPacket <= 0 || maxPacket > MaxPacket {
		maxPacket = MaxPacket
	}
	if maxPacket < MinPacket {
		maxPacket = MinPacket
	}
	n := int(h.Length)
	if n < MinPacket {
		return Packet{}, fmt.Errorf("%w: declared %d", ErrInvalidLength, n)
	}
	if n > maxPacket {
		return Packet{}, fmt.Errorf("%w: declared %d max %d", ErrInvalidLength, n, maxPacket)
	}
	if n > len(datagram) {
		return Packet{}, fmt.Errorf("%w: declared %d datagram %d", ErrInvalidLength, n, len(datagram))
	}
	attrs, err := decodeAttrs(datagram[HeaderLen:n], maxAttrs, maxValueBytes)
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		Code:          h.Code,
		Identifier:    h.Identifier,
		Authenticator: h.Authenticator,
		Attrs:         attrs,
	}, nil
}

func declaredSlice(packet []byte) ([]byte, Header, error) {
	if len(packet) < HeaderLen {
		return nil, Header{}, ErrHeaderShort
	}
	h, err := DecodeHeader(packet)
	if err != nil {
		return nil, Header{}, err
	}
	n := int(h.Length)
	if n < MinPacket || n > MaxPacket || n > len(packet) {
		return nil, Header{}, ErrInvalidLength
	}
	return packet[:n], h, nil
}

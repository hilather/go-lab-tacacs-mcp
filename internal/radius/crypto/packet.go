package crypto

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

func declaredHeader(packet []byte) (codec.Header, []byte, error) {
	if len(packet) < codec.HeaderSize {
		return codec.Header{}, nil, ErrPacketShort
	}
	h, err := codec.DecodeHeader(packet)
	if err != nil {
		return codec.Header{}, nil, err
	}
	n := int(h.Length)
	if n < codec.MinPacketBytes || n > codec.MaxPacketBytes || n > len(packet) {
		return codec.Header{}, nil, ErrInvalidLength
	}
	return h, packet[:n], nil
}

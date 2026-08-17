package tls

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

// ErrInvalidStreamLength is a framing error. The connection must close.
var ErrInvalidStreamLength = errors.New("radius/tls: invalid RADIUS stream length")

// ReadPacket reads one RADIUS packet from a TLS stream using the header
// Length field (RFC 6613 §2.6). It never returns bytes beyond Length.
func ReadPacket(r io.Reader, max int) ([]byte, error) {
	if max < codec.MinPacketBytes {
		max = codec.MinPacketBytes
	}
	if max > codec.MaxPacketBytes {
		max = codec.MaxPacketBytes
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < codec.MinPacketBytes || length > max {
		return nil, ErrInvalidStreamLength
	}
	buf := make([]byte, length)
	copy(buf, hdr[:])
	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// WritePacket writes exactly one RADIUS packet. The caller must pass the
// declared Length bytes and nothing more.
func WritePacket(w io.Writer, pkt []byte) error {
	if len(pkt) < codec.MinPacketBytes {
		return ErrInvalidStreamLength
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return ErrInvalidStreamLength
	}
	_, err := w.Write(pkt)
	return err
}

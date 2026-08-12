package codec

import (
	"encoding/binary"
	"fmt"
	"io"
)

// NewSessionID reads 4 cryptographically strong bytes. The codec never
// overwrites a client-supplied Header.SessionID.
func NewSessionID(r io.Reader) (uint32, error) {
	if r == nil {
		return 0, ErrEntropy
	}
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrEntropy, err)
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

package codec

import (
	"encoding/binary"
	"fmt"
)

type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remain() int { return len(c.b) - c.off }

func (c *cursor) u8() (byte, error) {
	if c.remain() < 1 {
		return 0, ErrLengthMismatch
	}
	v := c.b[c.off]
	c.off++
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if c.remain() < 2 {
		return 0, ErrLengthMismatch
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v, nil
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if n < 0 || c.remain() < n {
		return nil, ErrLengthMismatch
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]byte, n)
	copy(out, c.b[c.off:c.off+n])
	c.off += n
	return out, nil
}

func (c *cursor) done() error {
	if c.off != len(c.b) {
		return fmt.Errorf("%w: leftover %d", ErrLengthMismatch, len(c.b)-c.off)
	}
	return nil
}

func u8len(b []byte) (byte, error) {
	if len(b) > 255 {
		return 0, ErrFieldTooLong
	}
	return byte(len(b)), nil
}

func u16len(b []byte) (uint16, error) {
	if len(b) > 65535 {
		return 0, ErrFieldTooLong
	}
	return uint16(len(b)), nil
}

func checkBodyCap(n int) error {
	if n < 0 || n > MaxBodyBytes {
		return ErrBodyTooLarge
	}
	return nil
}

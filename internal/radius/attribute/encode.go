package attribute

import "fmt"

// Encode writes the canonical Type/Length/Value stream. It fails if any
// Value is longer than 253 bytes.
func Encode(set RawSet) ([]byte, error) {
	n := 0
	for _, a := range set {
		if len(a.Value) > MaxValueLength {
			return nil, fmt.Errorf("%w: type %d value %d", ErrValueTooLong, a.Type, len(a.Value))
		}
		n += 2 + len(a.Value)
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	off := 0
	for _, a := range set {
		out[off] = a.Type
		out[off+1] = byte(2 + len(a.Value))
		copy(out[off+2:], a.Value)
		off += 2 + len(a.Value)
	}
	return out, nil
}

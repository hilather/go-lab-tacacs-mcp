package attribute

import "fmt"

// Decode walks a RADIUS attribute payload. Every Length must be at least 2
// and within the remaining bytes. Order, duplicates, and unknown types are
// preserved. Values are copied so the result does not alias payload.
func Decode(payload []byte, maxAttrs, maxValueBytes int) (RawSet, error) {
	if maxAttrs <= 0 {
		maxAttrs = DefaultMaxAttributes
	}
	if maxValueBytes <= 0 {
		maxValueBytes = DefaultMaxValueBytes
	}
	out := make(RawSet, 0, 4)
	valueBytes := 0
	off := 0
	for off < len(payload) {
		remain := len(payload) - off
		if remain < 2 {
			return nil, fmt.Errorf("%w: leftover %d", ErrOverflow, remain)
		}
		typ := payload[off]
		alen := int(payload[off+1])
		if alen < 2 {
			return nil, fmt.Errorf("%w: type %d length %d", ErrLength, typ, alen)
		}
		if alen > remain {
			return nil, fmt.Errorf("%w: type %d length %d remain %d", ErrOverflow, typ, alen, remain)
		}
		if len(out) >= maxAttrs {
			return nil, fmt.Errorf("%w: max %d", ErrTooMany, maxAttrs)
		}
		vlen := alen - 2
		if valueBytes+vlen > maxValueBytes {
			return nil, fmt.Errorf("%w: have %d need %d max %d", ErrBudget, valueBytes, vlen, maxValueBytes)
		}
		var val []byte
		if vlen > 0 {
			val = make([]byte, vlen)
			copy(val, payload[off+2:off+alen])
		}
		out = append(out, Raw{Type: typ, Value: val})
		valueBytes += vlen
		off += alen
	}
	return out, nil
}

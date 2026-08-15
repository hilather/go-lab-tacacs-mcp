package codec

import "fmt"

// Attr is one independent Type/Value TLV. Wire Length is 2+len(Value).
type Attr struct {
	Type  uint8
	Value []byte
}

// Clone copies Value so the result does not alias a.
func (a Attr) Clone() Attr {
	if len(a.Value) == 0 {
		return Attr{Type: a.Type}
	}
	v := make([]byte, len(a.Value))
	copy(v, a.Value)
	return Attr{Type: a.Type, Value: v}
}

// First returns the first attribute of typ.
func First(attrs []Attr, typ uint8) (Attr, bool) {
	for _, a := range attrs {
		if a.Type == typ {
			return a, true
		}
	}
	return Attr{}, false
}

// AllOf returns every attribute of typ, in order.
func AllOf(attrs []Attr, typ uint8) []Attr {
	var out []Attr
	for _, a := range attrs {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

// CloneAttrs deep-copies every attribute.
func CloneAttrs(attrs []Attr) []Attr {
	if attrs == nil {
		return nil
	}
	out := make([]Attr, len(attrs))
	for i, a := range attrs {
		out[i] = a.Clone()
	}
	return out
}

func valueBytes(attrs []Attr) int {
	n := 0
	for _, a := range attrs {
		n += len(a.Value)
	}
	return n
}

// encodeAttrs writes Type/Length/Value. Values longer than 253 fail.
func encodeAttrs(attrs []Attr) ([]byte, error) {
	n := 0
	for _, a := range attrs {
		if len(a.Value) > MaxValue {
			return nil, fmt.Errorf("%w: type %d value %d", ErrAttrValueLong, a.Type, len(a.Value))
		}
		n += 2 + len(a.Value)
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	off := 0
	for _, a := range attrs {
		out[off] = a.Type
		out[off+1] = byte(2 + len(a.Value))
		copy(out[off+2:], a.Value)
		off += 2 + len(a.Value)
	}
	return out, nil
}

// decodeAttrs walks a payload. Length must be ≥ 2 and inside remain.
// Order, duplicates, and unknown types are kept. Values are copied.
func decodeAttrs(payload []byte, maxAttrs, maxValueBytes int) ([]Attr, error) {
	if maxAttrs <= 0 {
		maxAttrs = MaxAttrs
	}
	if maxValueBytes <= 0 {
		maxValueBytes = MaxValues
	}
	out := make([]Attr, 0, 4)
	used := 0
	i := 0
	for i < len(payload) {
		left := len(payload) - i
		if left < 2 {
			return nil, fmt.Errorf("%w: leftover %d", ErrAttrOverflow, left)
		}
		typ := payload[i]
		n := int(payload[i+1])
		if n < 2 {
			return nil, fmt.Errorf("%w: type %d length %d", ErrAttrLength, typ, n)
		}
		if n > left {
			return nil, fmt.Errorf("%w: type %d length %d remain %d", ErrAttrOverflow, typ, n, left)
		}
		if len(out) >= maxAttrs {
			return nil, fmt.Errorf("%w: max %d", ErrTooManyAttrs, maxAttrs)
		}
		vlen := n - 2
		if used+vlen > maxValueBytes {
			return nil, fmt.Errorf("%w: have %d need %d max %d", ErrAttrBudget, used, vlen, maxValueBytes)
		}
		var val []byte
		if vlen > 0 {
			val = make([]byte, vlen)
			copy(val, payload[i+2:i+n])
		}
		out = append(out, Attr{Type: typ, Value: val})
		used += vlen
		i += n
	}
	return out, nil
}

// VSA is type-26 vendor-id plus an undistinguished payload.
type VSA struct {
	Vendor  uint32
	Payload []byte
}

// ParseVSA reads vendor-id || payload from a type-26 Attr.
func ParseVSA(a Attr) (VSA, error) {
	if a.Type != TypeVendorSpecific {
		return VSA{}, fmt.Errorf("%w: type %d", ErrNotVSA, a.Type)
	}
	if len(a.Value) < 4 {
		return VSA{}, fmt.Errorf("%w: got %d", ErrVSAShort, len(a.Value))
	}
	vendor := uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
	v := VSA{Vendor: vendor}
	if rest := a.Value[4:]; len(rest) > 0 {
		v.Payload = make([]byte, len(rest))
		copy(v.Payload, rest)
	}
	return v, nil
}

// Attr encodes vendor-id || payload as type 26.
func (v VSA) Attr() (Attr, error) {
	if len(v.Payload) > MaxValue-4 {
		return Attr{}, fmt.Errorf("%w: payload %d", ErrVSAValueLong, len(v.Payload))
	}
	val := make([]byte, 4+len(v.Payload))
	val[0] = byte(v.Vendor >> 24)
	val[1] = byte(v.Vendor >> 16)
	val[2] = byte(v.Vendor >> 8)
	val[3] = byte(v.Vendor)
	copy(val[4:], v.Payload)
	return Attr{Type: TypeVendorSpecific, Value: val}, nil
}

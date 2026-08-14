package attribute

// Raw is one wire TLV: Type and Value. Length on the wire is 2+len(Value).
type Raw struct {
	Type  uint8
	Value []byte
}

// WireLength is the on-wire Type+Length+Value size.
func (r Raw) WireLength() int {
	return 2 + len(r.Value)
}

// Clone returns a copy whose Value does not alias r.Value.
func (r Raw) Clone() Raw {
	if len(r.Value) == 0 {
		return Raw{Type: r.Type}
	}
	v := make([]byte, len(r.Value))
	copy(v, r.Value)
	return Raw{Type: r.Type, Value: v}
}

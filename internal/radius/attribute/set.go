package attribute

// RawSet is an ordered, duplicate-preserving list of raw attributes.
type RawSet []Raw

// Len is the number of attributes, including duplicates and unknown types.
func (s RawSet) Len() int { return len(s) }

// ValueBytes is the sum of Value lengths (not including Type/Length octets).
func (s RawSet) ValueBytes() int {
	n := 0
	for _, a := range s {
		n += len(a.Value)
	}
	return n
}

// WireSize is the encoded attribute payload size.
func (s RawSet) WireSize() int {
	n := 0
	for _, a := range s {
		n += a.WireLength()
	}
	return n
}

// First returns the first attribute of typ.
func (s RawSet) First(typ uint8) (Raw, bool) {
	for _, a := range s {
		if a.Type == typ {
			return a, true
		}
	}
	return Raw{}, false
}

// AllOf returns every attribute of typ, in order.
func (s RawSet) AllOf(typ uint8) RawSet {
	var out RawSet
	for _, a := range s {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

// Clone deep-copies the set and every Value.
func (s RawSet) Clone() RawSet {
	if s == nil {
		return nil
	}
	out := make(RawSet, len(s))
	for i, a := range s {
		out[i] = a.Clone()
	}
	return out
}

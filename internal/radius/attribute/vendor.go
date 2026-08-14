package attribute

import (
	"encoding/binary"
	"fmt"
)

const vendorIDSize = 4

// VSA is Vendor-Specific (type 26) framing: a 32-bit vendor id and an
// undistinguished payload. Nested vendor-type dictionaries are not applied.
type VSA struct {
	Vendor  uint32
	Payload []byte
}

// ParseVSA reads vendor-id + payload from a type-26 Raw. Short or non-26
// attributes fail; the caller still keeps the Raw for unknown/malformed VSAs.
func ParseVSA(r Raw) (VSA, error) {
	if r.Type != TypeVendorSpecific {
		return VSA{}, fmt.Errorf("%w: type %d", ErrNotVSA, r.Type)
	}
	if len(r.Value) < vendorIDSize {
		return VSA{}, fmt.Errorf("%w: got %d", ErrVSAShort, len(r.Value))
	}
	v := VSA{Vendor: binary.BigEndian.Uint32(r.Value[:vendorIDSize])}
	if rest := r.Value[vendorIDSize:]; len(rest) > 0 {
		v.Payload = make([]byte, len(rest))
		copy(v.Payload, rest)
	}
	return v, nil
}

// Raw encodes vendor-id || payload as type 26. Payload must fit in one TLV.
func (v VSA) Raw() (Raw, error) {
	if len(v.Payload) > MaxValueLength-vendorIDSize {
		return Raw{}, fmt.Errorf("%w: payload %d", ErrVSAValueLong, len(v.Payload))
	}
	val := make([]byte, vendorIDSize+len(v.Payload))
	binary.BigEndian.PutUint32(val[:vendorIDSize], v.Vendor)
	copy(val[vendorIDSize:], v.Payload)
	return Raw{Type: TypeVendorSpecific, Value: val}, nil
}

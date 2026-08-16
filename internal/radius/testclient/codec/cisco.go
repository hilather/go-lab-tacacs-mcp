package codec

import "fmt"

// Independent Cisco VSA constants. Must not import production attribute.
const (
	VendorCisco     uint32 = 9
	TypeCiscoAVPair uint8  = 1
)

// VendorTLV is one nested vendor-type/length/value. Independent of production.
type VendorTLV struct {
	Type  uint8
	Value []byte
}

// ParseVendorTLVs walks a VSA payload as 1-byte type + 1-byte length.
// Unknown types stay raw. Leftover or illegal length fails closed.
func ParseVendorTLVs(payload []byte) ([]VendorTLV, error) {
	if len(payload) == 0 {
		return []VendorTLV{}, nil
	}
	out := make([]VendorTLV, 0, 2)
	i := 0
	for i < len(payload) {
		left := len(payload) - i
		if left < 2 {
			return nil, fmt.Errorf("%w: leftover %d", ErrVendorTLV, left)
		}
		typ := payload[i]
		n := int(payload[i+1])
		if n < 2 {
			return nil, fmt.Errorf("%w: type %d length %d", ErrVendorTLV, typ, n)
		}
		if n > left {
			return nil, fmt.Errorf("%w: type %d length %d remain %d", ErrVendorTLV, typ, n, left)
		}
		var val []byte
		if vlen := n - 2; vlen > 0 {
			val = make([]byte, vlen)
			copy(val, payload[i+2:i+n])
		}
		out = append(out, VendorTLV{Type: typ, Value: val})
		i += n
	}
	return out, nil
}

// EncodeVendorTLVs writes nested type/length/value independently of production.
func EncodeVendorTLVs(tlvs []VendorTLV) ([]byte, error) {
	n := 0
	for _, t := range tlvs {
		if len(t.Value) > MaxValue-6 {
			return nil, fmt.Errorf("%w: type %d value %d", ErrVendorTLVLong, t.Type, len(t.Value))
		}
		n += 2 + len(t.Value)
	}
	if n == 0 {
		return []byte{}, nil
	}
	if n > MaxValue-4 {
		return nil, fmt.Errorf("%w: payload %d", ErrVSAValueLong, n)
	}
	out := make([]byte, n)
	off := 0
	for _, t := range tlvs {
		out[off] = t.Type
		out[off+1] = byte(2 + len(t.Value))
		copy(out[off+2:], t.Value)
		off += 2 + len(t.Value)
	}
	return out, nil
}

// EncodeCiscoAVPair encodes vendor 9 / type 1 as a type-26 Attr.
func EncodeCiscoAVPair(text string) (Attr, error) {
	payload, err := EncodeVendorTLVs([]VendorTLV{{Type: TypeCiscoAVPair, Value: []byte(text)}})
	if err != nil {
		return Attr{}, err
	}
	return (VSA{Vendor: VendorCisco, Payload: payload}).Attr()
}

// DecodeCiscoAVPairs returns every vendor-type 1 text from a type-26 Attr.
func DecodeCiscoAVPairs(a Attr) ([]string, error) {
	vsa, err := ParseVSA(a)
	if err != nil {
		return nil, err
	}
	if vsa.Vendor != VendorCisco {
		return nil, nil
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tlvs))
	for _, tlv := range tlvs {
		if tlv.Type == TypeCiscoAVPair {
			out = append(out, string(tlv.Value))
		}
	}
	return out, nil
}

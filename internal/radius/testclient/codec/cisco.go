package codec

// Independent Cisco VSA constants. Must not import production attribute.
const (
	VendorCisco     uint32 = 9
	TypeCiscoAVPair uint8  = 1
)

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

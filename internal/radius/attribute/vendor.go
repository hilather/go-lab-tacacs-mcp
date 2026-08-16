package attribute

import (
	"encoding/binary"
	"fmt"
)

const vendorIDSize = 4

// Microsoft vendor id (RFC 2548). Reserved from operator dictionaries.
const VendorMicrosoft uint32 = 311

// RFC 2548 Microsoft vendor-types used by RADIUS MS-CHAP.
const (
	VendorTypeMSCHAPResponse  uint8 = 1
	VendorTypeMSCHAPError     uint8 = 2
	VendorTypeMSCHAPChallenge uint8 = 11
	VendorTypeMSCHAP2Response uint8 = 25
	VendorTypeMSCHAP2Success  uint8 = 26
)

const (
	MSCHAPChallengeV1Len  = 8
	MSCHAPChallengeV2Len  = 16
	MSCHAPResponseWireLen = 50
	MSCHAP2SuccessWireLen = 43 // Ident + RFC 2759 AuthenticatorResponse
)

// Cisco vendor id and the only named nested type in this program.
const (
	VendorCisco     uint32 = 9
	TypeCiscoAVPair uint8  = 1
	NameCiscoAVPair        = "Cisco-AVPair"
)

// MaxVendorTLVValue is the largest nested vendor-type value that still
// fits in one type-26 attribute (253 − 4 vendor-id − 2 TLV header).
const MaxVendorTLVValue = MaxValueLength - vendorIDSize - 2

// VSA is Vendor-Specific (type 26) framing: a 32-bit vendor id and an
// undistinguished payload. Nested vendor-type dictionaries are applied by ParseVendorTLVs.
type VSA struct {
	Vendor  uint32
	Payload []byte
}

// VendorTLV is one nested vendor-type / vendor-length / value tuple.
// Length on the wire includes the type and length octets.
type VendorTLV struct {
	Type  uint8
	Value []byte
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

// ParseVendorTLVs walks a vendor payload as 1-byte type + 1-byte length TLVs.
// Unknown types stay raw. A leftover byte, length < 2, or length past the
// remaining payload is malformed — callers must not guess.
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

// EncodeVendorTLVs writes nested type/length/value. Each value must fit
// in one type-26 payload together with the vendor id.
func EncodeVendorTLVs(tlvs []VendorTLV) ([]byte, error) {
	n := 0
	for _, t := range tlvs {
		if len(t.Value) > MaxVendorTLVValue {
			return nil, fmt.Errorf("%w: type %d value %d", ErrVendorTLVLong, t.Type, len(t.Value))
		}
		n += 2 + len(t.Value)
	}
	if n == 0 {
		return []byte{}, nil
	}
	if n > MaxValueLength-vendorIDSize {
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

// MicrosoftVSA encodes one RFC 2548 Microsoft TLV as type 26.
func MicrosoftVSA(vendorType uint8, value []byte) (Raw, error) {
	payload, err := EncodeVendorTLVs([]VendorTLV{{Type: vendorType, Value: value}})
	if err != nil {
		return Raw{}, err
	}
	return (VSA{Vendor: VendorMicrosoft, Payload: payload}).Raw()
}

// MicrosoftSecret reports whether a type-26 raw holds a Microsoft MS-CHAP
// vendor type. Malformed vendor-311 payloads are treated as secret.
func MicrosoftSecret(r Raw) bool {
	if r.Type != TypeVendorSpecific {
		return false
	}
	vsa, err := ParseVSA(r)
	if err != nil || vsa.Vendor != VendorMicrosoft {
		return false
	}
	tlvs, err := ParseVendorTLVs(vsa.Payload)
	if err != nil {
		return true
	}
	for _, t := range tlvs {
		switch t.Type {
		case VendorTypeMSCHAPResponse, VendorTypeMSCHAPError, VendorTypeMSCHAPChallenge,
			VendorTypeMSCHAP2Response, VendorTypeMSCHAP2Success:
			return true
		}
	}
	return false
}

// EncodeCiscoAVPair encodes one named Cisco-AVPair as type 26 / vendor 9 / type 1.
func EncodeCiscoAVPair(text string) (Raw, error) {
	payload, err := EncodeVendorTLVs([]VendorTLV{{Type: TypeCiscoAVPair, Value: []byte(text)}})
	if err != nil {
		return Raw{}, err
	}
	return (VSA{Vendor: VendorCisco, Payload: payload}).Raw()
}

// CiscoAVPairKey is the dictionary identity for named Cisco-AVPair.
func CiscoAVPairKey() Key {
	return Key{Vendor: VendorCisco, Code: uint32(TypeCiscoAVPair), Space: SpaceVSA}
}

// DecodeCiscoAVPairs returns every vendor-type 1 text from a type-26 Raw.
// Unknown nested types are skipped. Malformed nested TLVs fail closed.
func DecodeCiscoAVPairs(r Raw) ([]string, error) {
	vsa, err := ParseVSA(r)
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

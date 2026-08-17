package testclient

import (
	"crypto/md5"
	"fmt"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

// Independent EAP codes and types (RFC 3748). Not production constants.
const (
	EAPCodeRequest  = 1
	EAPCodeResponse = 2
	EAPCodeSuccess  = 3
	EAPCodeFailure  = 4

	EAPTypeIdentity = 1
	EAPTypeNAK      = 3
	EAPTypeMD5      = 4
)

// EAPPacket is one concatenated EAP message built by the independent client.
type EAPPacket struct {
	Code       byte
	Identifier byte
	Type       byte
	Data       []byte
	HasType    bool
}

// EncodeEAP writes Code || Identifier || Length || [Type || Type-Data].
func EncodeEAP(p EAPPacket) []byte {
	if p.Code == EAPCodeSuccess || p.Code == EAPCodeFailure {
		return []byte{p.Code, p.Identifier, 0, 4}
	}
	n := 5 + len(p.Data)
	out := make([]byte, n)
	out[0] = p.Code
	out[1] = p.Identifier
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	out[4] = p.Type
	copy(out[5:], p.Data)
	return out
}

// DecodeEAP parses one concatenated EAP packet. Length must match the buffer.
func DecodeEAP(b []byte) (EAPPacket, error) {
	if len(b) < 4 {
		return EAPPacket{}, fmt.Errorf("eap: short header %d", len(b))
	}
	length := int(b[2])<<8 | int(b[3])
	if length != len(b) || length < 4 {
		return EAPPacket{}, fmt.Errorf("eap: length %d buffer %d", length, len(b))
	}
	p := EAPPacket{Code: b[0], Identifier: b[1]}
	switch p.Code {
	case EAPCodeSuccess, EAPCodeFailure:
		if length != 4 {
			return EAPPacket{}, fmt.Errorf("eap: success/failure length %d", length)
		}
		return p, nil
	case EAPCodeRequest, EAPCodeResponse:
		if length < 5 {
			return EAPPacket{}, fmt.Errorf("eap: request/response length %d", length)
		}
		p.HasType = true
		p.Type = b[4]
		if length > 5 {
			p.Data = append([]byte(nil), b[5:]...)
		}
		return p, nil
	default:
		return EAPPacket{}, fmt.Errorf("eap: unknown code %d", p.Code)
	}
}

// ConcatEAPMessage concatenates EAP-Message attribute values in order.
func ConcatEAPMessage(attrs []codec.Attr) []byte {
	all := codec.AllOf(attrs, codec.TypeEAPMessage)
	if len(all) == 0 {
		return nil
	}
	n := 0
	for _, a := range all {
		n += len(a.Value)
	}
	out := make([]byte, 0, n)
	for _, a := range all {
		out = append(out, a.Value...)
	}
	return out
}

// EAPMessageAttr wraps one EAP packet as a single EAP-Message attribute.
func EAPMessageAttr(p EAPPacket) codec.Attr {
	return codec.Attr{Type: codec.TypeEAPMessage, Value: EncodeEAP(p)}
}

// EAPIdentityResponse is EAP-Response/Identity.
func EAPIdentityResponse(id byte, identity string) EAPPacket {
	return EAPPacket{Code: EAPCodeResponse, Identifier: id, Type: EAPTypeIdentity, HasType: true, Data: []byte(identity)}
}

// EAPMD5Response is EAP-Response/MD5-Challenge (Value-Size || hash).
func EAPMD5Response(id byte, hash []byte) EAPPacket {
	data := make([]byte, 1+len(hash))
	data[0] = byte(len(hash))
	copy(data[1:], hash)
	return EAPPacket{Code: EAPCodeResponse, Identifier: id, Type: EAPTypeMD5, HasType: true, Data: data}
}

// EAPTypeResponse is a typed EAP-Response used for unsupported-method tests.
func EAPTypeResponse(id, typ byte, data []byte) EAPPacket {
	return EAPPacket{Code: EAPCodeResponse, Identifier: id, Type: typ, HasType: true, Data: append([]byte(nil), data...)}
}

// ParseMD5Challenge extracts the 16-octet Value from EAP-Request/MD5-Challenge.
func ParseMD5Challenge(p EAPPacket) ([]byte, error) {
	if p.Code != EAPCodeRequest || p.Type != EAPTypeMD5 || len(p.Data) < 1 {
		return nil, fmt.Errorf("eap: not an MD5-Challenge request")
	}
	n := int(p.Data[0])
	if n < 1 || len(p.Data) < 1+n {
		return nil, fmt.Errorf("eap: MD5-Challenge value-size %d", n)
	}
	out := make([]byte, n)
	copy(out, p.Data[1:1+n])
	return out, nil
}

// MD5Response is the independent CHAP-in-EAP hash: MD5(id || secret || challenge).
func MD5Response(id byte, secret, challenge []byte) []byte {
	h := md5.New()
	_, _ = h.Write([]byte{id})
	_, _ = h.Write(secret)
	_, _ = h.Write(challenge)
	return h.Sum(nil)
}

// FirstState copies the State attribute value.
func FirstState(attrs []codec.Attr) ([]byte, bool) {
	a, ok := codec.First(attrs, codec.TypeState)
	if !ok || len(a.Value) == 0 {
		return nil, false
	}
	out := make([]byte, len(a.Value))
	copy(out, a.Value)
	return out, true
}

// FirstEAP decodes the concatenated EAP-Message attributes.
func FirstEAP(attrs []codec.Attr) (EAPPacket, error) {
	return DecodeEAP(ConcatEAPMessage(attrs))
}

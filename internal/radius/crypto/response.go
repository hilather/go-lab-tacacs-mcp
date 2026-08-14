package crypto

import (
	"encoding/binary"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

// ResponseAuthenticator is MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
// (RFC 2865 §3). Used for Access-Accept/Reject/Challenge and
// Accounting-Response. length must equal 20+len(encoded attrs), or be 0
// to compute that value.
func ResponseAuthenticator(secret []byte, code codec.Code, id uint8, length uint16, reqAuth [16]byte, attrs attribute.RawSet) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	attrBytes, err := attribute.Encode(attrs)
	if err != nil {
		return zero, err
	}
	computed := uint16(codec.HeaderSize + len(attrBytes))
	if length == 0 {
		length = computed
	} else if length != computed {
		return zero, ErrLengthMismatch
	}
	var hdr [4]byte
	hdr[0] = byte(code)
	hdr[1] = id
	binary.BigEndian.PutUint16(hdr[2:4], length)
	return md5Concat(hdr[:], reqAuth[:], attrBytes, secret), nil
}

// ValidateResponseAuthenticator checks packet's Authenticator against
// ResponseAuthenticator using reqAuth from the matching request.
func ValidateResponseAuthenticator(secret []byte, packet []byte, reqAuth [16]byte) error {
	h, declared, err := declaredHeader(packet)
	if err != nil {
		return err
	}
	attrs, err := attribute.Decode(declared[codec.HeaderSize:], 0, 0)
	if err != nil {
		return err
	}
	want, err := ResponseAuthenticator(secret, h.Code, h.Identifier, h.Length, reqAuth, attrs)
	if err != nil {
		return err
	}
	if !equal16(h.Authenticator, want) {
		return ErrInvalidResponseAuthenticator
	}
	return nil
}

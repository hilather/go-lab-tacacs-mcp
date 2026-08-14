package crypto

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

const messageAuthenticatorWireLen = 18

// MessageAuthenticator is HMAC-MD5 over the declared packet with every
// Message-Authenticator value replaced by 16 zero octets (RFC 2869 §5.14,
// RFC 3579 §3.2). Exactly one 16-octet Message-Authenticator must be present.
func MessageAuthenticator(secret []byte, packet []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	work, err := packetWithZeroedMA(packet)
	if err != nil {
		return zero, err
	}
	return hmacMD5(secret, work), nil
}

// ValidateMessageAuthenticator recomputes MessageAuthenticator and compares
// the on-wire value in constant time. Missing, duplicate, or wrong-length
// attributes fail before the HMAC.
func ValidateMessageAuthenticator(secret []byte, packet []byte) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}
	got, err := messageAuthenticatorValue(packet)
	if err != nil {
		return err
	}
	want, err := MessageAuthenticator(secret, packet)
	if err != nil {
		return err
	}
	if !Equal(got, want[:]) {
		return ErrInvalidMessageAuthenticator
	}
	return nil
}

func messageAuthenticatorValue(packet []byte) ([]byte, error) {
	_, declared, err := declaredHeader(packet)
	if err != nil {
		return nil, err
	}
	attrs, err := attribute.Decode(declared[codec.HeaderSize:], 0, 0)
	if err != nil {
		return nil, err
	}
	found := attrs.AllOf(attribute.TypeMessageAuthenticator)
	switch found.Len() {
	case 0:
		return nil, ErrMissingMessageAuthenticator
	case 1:
		if len(found[0].Value) != codec.AuthenticatorSize {
			return nil, ErrInvalidMessageAuthenticator
		}
		v := make([]byte, codec.AuthenticatorSize)
		copy(v, found[0].Value)
		return v, nil
	default:
		return nil, ErrDuplicateMessageAuthenticator
	}
}

func packetWithZeroedMA(packet []byte) ([]byte, error) {
	_, declared, err := declaredHeader(packet)
	if err != nil {
		return nil, err
	}
	attrs, err := attribute.Decode(declared[codec.HeaderSize:], 0, 0)
	if err != nil {
		return nil, err
	}
	found := attrs.AllOf(attribute.TypeMessageAuthenticator)
	switch found.Len() {
	case 0:
		return nil, ErrMissingMessageAuthenticator
	case 1:
		if len(found[0].Value) != codec.AuthenticatorSize {
			return nil, ErrInvalidMessageAuthenticator
		}
	default:
		return nil, ErrDuplicateMessageAuthenticator
	}
	work := make([]byte, len(declared))
	copy(work, declared)
	off := codec.HeaderSize
	cleared := 0
	for off+2 <= len(work) {
		alen := int(work[off+1])
		if alen < 2 || off+alen > len(work) {
			return nil, ErrInvalidLength
		}
		if work[off] == attribute.TypeMessageAuthenticator {
			if alen != messageAuthenticatorWireLen {
				return nil, ErrInvalidMessageAuthenticator
			}
			for i := 0; i < codec.AuthenticatorSize; i++ {
				work[off+2+i] = 0
			}
			cleared++
		}
		off += alen
	}
	if cleared != 1 {
		return nil, ErrInvalidMessageAuthenticator
	}
	return work, nil
}

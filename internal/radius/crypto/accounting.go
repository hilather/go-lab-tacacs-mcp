package crypto

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
)

// AccountingRequestAuthenticator is MD5(Code+ID+Length+16zero+Attributes+Secret)
// (RFC 2866 §3). The Authenticator field of packetWithoutAuth is ignored
// and treated as 16 zero octets so a received packet can be validated.
// Present Message-Authenticator values are zeroed for the checksum
// (RFC 2869 §5.14 / RFC 3579 §3.2) so inbound MA does not invalidate
// an otherwise correct Request Authenticator.
func AccountingRequestAuthenticator(secret []byte, packetWithoutAuth []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	_, declared, err := declaredHeader(packetWithoutAuth)
	if err != nil {
		return zero, err
	}
	attrs := zeroAccountingMA(declared[codec.HeaderSize:])
	return md5Concat(declared[:4], zero[:], attrs, secret), nil
}

// zeroAccountingMA copies attrs and replaces every 16-octet
// Message-Authenticator value with zeros. Absent MA is a no-op.
func zeroAccountingMA(attrs []byte) []byte {
	work := append([]byte(nil), attrs...)
	off := 0
	for off+2 <= len(work) {
		alen := int(work[off+1])
		if alen < 2 || off+alen > len(work) {
			break
		}
		if work[off] == attribute.TypeMessageAuthenticator && alen == messageAuthenticatorWireLen {
			for i := 0; i < codec.AuthenticatorSize; i++ {
				work[off+2+i] = 0
			}
		}
		off += alen
	}
	return work
}

// ValidateAccountingRequestAuthenticator compares the packet Authenticator
// to AccountingRequestAuthenticator using constant-time Equal.
func ValidateAccountingRequestAuthenticator(secret []byte, packet []byte) error {
	h, _, err := declaredHeader(packet)
	if err != nil {
		return err
	}
	want, err := AccountingRequestAuthenticator(secret, packet)
	if err != nil {
		return err
	}
	if !equal16(h.Authenticator, want) {
		return ErrInvalidAccountingAuthenticator
	}
	return nil
}

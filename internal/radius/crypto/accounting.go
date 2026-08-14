package crypto

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"

// AccountingRequestAuthenticator is MD5(Code+ID+Length+16zero+Attributes+Secret)
// (RFC 2866 §3). The Authenticator field of packetWithoutAuth is ignored
// and treated as 16 zero octets so a received packet can be validated.
func AccountingRequestAuthenticator(secret []byte, packetWithoutAuth []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	_, declared, err := declaredHeader(packetWithoutAuth)
	if err != nil {
		return zero, err
	}
	return md5Concat(declared[:4], zero[:], declared[codec.HeaderSize:], secret), nil
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

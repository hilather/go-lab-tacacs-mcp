package crypto

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"

// DynAuthRequestAuthenticator is RFC 5176 §2.3 MD5 with a zero header
// Authenticator and the populated Message-Authenticator retained in attributes.
func DynAuthRequestAuthenticator(secret, packet []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	_, declared, err := declaredHeader(packet)
	if err != nil {
		return zero, err
	}
	return md5Concat(declared[:4], zero[:], declared[codec.HeaderSize:], secret), nil
}

// ValidateDynAuthRequestAuthenticator verifies the request checksum.
func ValidateDynAuthRequestAuthenticator(secret, packet []byte) error {
	h, _, err := declaredHeader(packet)
	if err != nil {
		return err
	}
	want, err := DynAuthRequestAuthenticator(secret, packet)
	if err != nil {
		return err
	}
	if !equal16(h.Authenticator, want) {
		return ErrInvalidDynAuthAuthenticator
	}
	return nil
}

// DynAuthMessageAuthenticator uses zero Request Authenticator and MA fields
// for CoA/Disconnect requests (RFC 5176 §3.4).
func DynAuthMessageAuthenticator(secret, packet []byte) ([16]byte, error) {
	var zero [16]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	work, err := packetWithZeroedMA(packet)
	if err != nil {
		return zero, err
	}
	clear(work[4:codec.HeaderSize])
	return hmacMD5(secret, work), nil
}

// ValidateDynAuthMessageAuthenticator verifies the request HMAC.
func ValidateDynAuthMessageAuthenticator(secret, packet []byte) error {
	got, err := messageAuthenticatorValue(packet)
	if err != nil {
		return err
	}
	want, err := DynAuthMessageAuthenticator(secret, packet)
	if err != nil {
		return err
	}
	if !Equal(got, want[:]) {
		return ErrInvalidMessageAuthenticator
	}
	return nil
}

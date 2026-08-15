package crypto

import "errors"

var (
	ErrEmptySecret = errors.New("radius crypto: shared secret is empty")

	ErrPacketShort    = errors.New("radius crypto: packet shorter than 20 bytes")
	ErrInvalidLength  = errors.New("radius crypto: declared length is invalid")
	ErrLengthMismatch = errors.New("radius crypto: length does not match attributes")

	ErrPasswordTooLong = errors.New("radius crypto: User-Password exceeds 128 octets")
	ErrHiddenPassword  = errors.New("radius crypto: User-Password hidden value is invalid")

	ErrMissingMessageAuthenticator   = errors.New("radius crypto: Message-Authenticator is missing")
	ErrDuplicateMessageAuthenticator = errors.New("radius crypto: more than one Message-Authenticator")
	ErrInvalidMessageAuthenticator   = errors.New("radius crypto: Message-Authenticator is invalid")

	ErrInvalidAccountingAuthenticator = errors.New("radius crypto: Accounting-Request Authenticator is invalid")
	ErrInvalidResponseAuthenticator   = errors.New("radius crypto: Response Authenticator is invalid")
)

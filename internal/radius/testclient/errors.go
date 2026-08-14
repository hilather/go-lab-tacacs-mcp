package testclient

import "errors"

var (
	// ErrInvalidResponseAuthenticator is testclient-only (design §5.7).
	// It is never a server discard/reject reason.
	ErrInvalidResponseAuthenticator = errors.New("client_reject_invalid_response_authenticator")

	// ErrInvalidMessageAuthenticator is returned when a response MA is
	// missing or does not validate.
	ErrInvalidMessageAuthenticator = errors.New("client_reject_invalid_message_authenticator")

	// ErrUnexpectedCode is a response whose Code is not the expected family.
	ErrUnexpectedCode = errors.New("testclient: unexpected RADIUS code")

	// ErrConflictingAuth is PAP and CHAP both set on one Access-Request.
	ErrConflictingAuth = errors.New("testclient: PAP and CHAP both set")

	// ErrMissingUserName is an Access-Request without User-Name.
	ErrMissingUserName = errors.New("testclient: User-Name is required")

	// ErrCHAPPasswordLength is a CHAP-Password that is not 17 octets.
	ErrCHAPPasswordLength = errors.New("testclient: CHAP-Password length is not 17")
)

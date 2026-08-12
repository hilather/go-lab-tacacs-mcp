package credentials

import (
	"errors"
	"fmt"
)

// Sentinel results. Error text is uniform and must never include secrets,
// usernames, challenges, or verifier encodings.
var (
	ErrFailed    = errors.New("credentials: authentication failed")
	ErrMalformed = errors.New("credentials: malformed authenticator")
	ErrInvalid   = errors.New("credentials: invalid material")
)

// FailureKind is an internal reason for redacted events. It is not safe to
// put on the TACACS wire. AAA maps KindMalformed to protocol ERROR and
// KindInvalid to internal ERROR. Every other Kind, including KindMissing,
// is TACACS FAIL. Error() for those FAIL kinds is always ErrFailed so a
// copied server_msg cannot leak method or user existence.
type FailureKind string

const (
	KindUnknown    FailureKind = "unknown_user"
	KindDisabled   FailureKind = "disabled"
	KindRestricted FailureKind = "restricted"
	KindExpired    FailureKind = "expired"
	KindWrong      FailureKind = "wrong"
	KindMissing    FailureKind = "missing"
	KindMalformed  FailureKind = "malformed"
	KindInvalid    FailureKind = "invalid"
)

// AuthError is the typed verification result. Error() is one of the sentinels.
type AuthError struct {
	Kind FailureKind
	err  error
}

func (e AuthError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return ErrFailed.Error()
}

func (e AuthError) Unwrap() error {
	if e.err != nil {
		return e.err
	}
	return ErrFailed
}

func (e AuthError) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, e.Error())
}

func fail(kind FailureKind) AuthError {
	return AuthError{Kind: kind, err: ErrFailed}
}

func unavailable() AuthError {
	return fail(KindMissing)
}

func malformed() AuthError {
	return AuthError{Kind: KindMalformed, err: ErrMalformed}
}

func invalidMaterial() AuthError {
	return AuthError{Kind: KindInvalid, err: ErrInvalid}
}

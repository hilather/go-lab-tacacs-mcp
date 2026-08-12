package codec

import "errors"

var (
	ErrLengthMismatch   = errors.New("tacacs body component lengths do not match packet length")
	ErrNonPrintable     = errors.New("tacacs text field is not printable US-ASCII")
	ErrFieldTooLong     = errors.New("tacacs field exceeds its length width")
	ErrTooManyArgs      = errors.New("tacacs argument count exceeds 255")
	ErrArgument         = errors.New("tacacs argument is not name plus = or *")
	ErrCHAPLength       = errors.New("tacacs CHAP data length is invalid")
	ErrMSCHAPLength     = errors.New("tacacs MS-CHAP data length is invalid")
	ErrAcctFlags        = errors.New("tacacs accounting flag combination is invalid")
	ErrFollow           = errors.New("tacacs FOLLOW status must not be emitted")
	ErrSeqUnexpected    = errors.New("tacacs sequence number is not next in session")
	ErrSeqParity        = errors.New("tacacs sequence number has wrong client or server parity")
	ErrSessionClosed    = errors.New("tacacs session is closed")
	ErrSessionMismatch  = errors.New("tacacs session id or type mismatch")
	ErrPrematurePacket  = errors.New("tacacs packet arrived before single-connect negotiation finished")
	ErrTooManyContinues = errors.New("tacacs authentication continuation limit exceeded")
	ErrEntropy          = errors.New("tacacs session id entropy is exhausted")
)

package codec

import "strconv"

// Code is the RADIUS packet Code octet (RFC 2865 §3, RFC 2866 §3).
type Code uint8

const (
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	// CodeAccessChallenge is recognized so it can be discarded later.
	// It is not an advertised MVP feature.
	CodeAccessChallenge Code = 11
)

// Known reports codes the codec understands, including Access-Challenge.
func (c Code) Known() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge:
		return true
	default:
		return false
	}
}

// Advertised reports MVP codes. Access-Challenge is known but not advertised.
func (c Code) Advertised() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse:
		return true
	default:
		return false
	}
}

// AccessFamily is Access-Request/Accept/Reject/Challenge.
func (c Code) AccessFamily() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject, CodeAccessChallenge:
		return true
	default:
		return false
	}
}

// AccountingFamily is Accounting-Request/Response.
func (c Code) AccountingFamily() bool {
	return c == CodeAccountingRequest || c == CodeAccountingResponse
}

// String is a diagnostic name. Access-Challenge is named for discard traces.
func (c Code) String() string {
	switch c {
	case CodeAccessRequest:
		return "Access-Request"
	case CodeAccessAccept:
		return "Access-Accept"
	case CodeAccessReject:
		return "Access-Reject"
	case CodeAccountingRequest:
		return "Accounting-Request"
	case CodeAccountingResponse:
		return "Accounting-Response"
	case CodeAccessChallenge:
		return "Access-Challenge"
	default:
		return "Code(" + strconv.Itoa(int(c)) + ")"
	}
}

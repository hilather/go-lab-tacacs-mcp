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
	// CodeAccessChallenge is emitted for EAP Identity/MD5 termination.
	CodeAccessChallenge Code = 11
	// RFC 5176 Dynamic Authorization (DAC originate in this program).
	CodeDisconnectRequest Code = 40
	CodeDisconnectACK     Code = 41
	CodeDisconnectNAK     Code = 42
	CodeCoARequest        Code = 43
	CodeCoAACK            Code = 44
	CodeCoANAK            Code = 45
)

// Known reports codes the codec understands, including Access-Challenge.
func (c Code) Known() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK:
		return true
	default:
		return false
	}
}

// Advertised reports shipped Access/Accounting codes, including Challenge.
func (c Code) Advertised() bool {
	switch c {
	case CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse, CodeAccessChallenge,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK:
		return true
	default:
		return false
	}
}

// DynamicAuthFamily is RFC 5176 CoA/Disconnect request and reply codes.
func (c Code) DynamicAuthFamily() bool {
	switch c {
	case CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK:
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
	case CodeDisconnectRequest:
		return "Disconnect-Request"
	case CodeDisconnectACK:
		return "Disconnect-ACK"
	case CodeDisconnectNAK:
		return "Disconnect-NAK"
	case CodeCoARequest:
		return "CoA-Request"
	case CodeCoAACK:
		return "CoA-ACK"
	case CodeCoANAK:
		return "CoA-NAK"
	default:
		return "Code(" + strconv.Itoa(int(c)) + ")"
	}
}

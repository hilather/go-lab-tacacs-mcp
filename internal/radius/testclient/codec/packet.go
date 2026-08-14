package codec

import "strconv"

const (
	HeaderLen = 20
	AuthLen   = 16
	MinPacket = 20
	MaxPacket = 4096
	MaxAttrs  = 256
	MaxValues = 4096
	MaxValue  = 253
)

// IETF type numbers used by the independent client. Named dictionary
// metadata is not implemented here.
const (
	TypeUserName             uint8 = 1
	TypeUserPassword         uint8 = 2
	TypeCHAPPassword         uint8 = 3
	TypeVendorSpecific       uint8 = 26
	TypeProxyState           uint8 = 33
	TypeAcctStatusType       uint8 = 40
	TypeAcctSessionID        uint8 = 44
	TypeCHAPChallenge        uint8 = 60
	TypeMessageAuthenticator uint8 = 80
)

// Code is the RADIUS Code octet. Values match RFC 2865/2866.
type Code uint8

const (
	AccessRequest      Code = 1
	AccessAccept       Code = 2
	AccessReject       Code = 3
	AccountingRequest  Code = 4
	AccountingResponse Code = 5
	// AccessChallenge is decoded so a later test can reject it.
	// It is not an advertised feature.
	AccessChallenge Code = 11
)

// Packet is one RADIUS datagram. Attrs are independent of production types.
type Packet struct {
	Code          Code
	Identifier    uint8
	Authenticator [AuthLen]byte
	Attrs         []Attr
}

// Header is the 20-byte prefix. Length is recorded only.
type Header struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [AuthLen]byte
}

// Known reports codes this copy understands, including Access-Challenge.
func (c Code) Known() bool {
	switch c {
	case AccessRequest, AccessAccept, AccessReject, AccountingRequest, AccountingResponse, AccessChallenge:
		return true
	default:
		return false
	}
}

// Advertised reports MVP codes. Access-Challenge is known but not advertised.
func (c Code) Advertised() bool {
	switch c {
	case AccessRequest, AccessAccept, AccessReject, AccountingRequest, AccountingResponse:
		return true
	default:
		return false
	}
}

// AccessFamily is Access-Request/Accept/Reject/Challenge.
func (c Code) AccessFamily() bool {
	switch c {
	case AccessRequest, AccessAccept, AccessReject, AccessChallenge:
		return true
	default:
		return false
	}
}

// AccountingFamily is Accounting-Request/Response.
func (c Code) AccountingFamily() bool {
	return c == AccountingRequest || c == AccountingResponse
}

// String is a diagnostic name. Authenticators are never included.
func (c Code) String() string {
	switch c {
	case AccessRequest:
		return "Access-Request"
	case AccessAccept:
		return "Access-Accept"
	case AccessReject:
		return "Access-Reject"
	case AccountingRequest:
		return "Accounting-Request"
	case AccountingResponse:
		return "Accounting-Response"
	case AccessChallenge:
		return "Access-Challenge"
	default:
		return "Code(" + strconv.Itoa(int(c)) + ")"
	}
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func put16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

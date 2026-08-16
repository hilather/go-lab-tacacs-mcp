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
	TypeNASIPAddress         uint8 = 4
	TypeNASPort              uint8 = 5
	TypeFramedIPAddress      uint8 = 8
	TypeReplyMessage         uint8 = 18
	TypeSessionTimeout       uint8 = 27
	TypeIdleTimeout          uint8 = 28
	TypeNASIdentifier        uint8 = 32
	TypeAcctSessionID        uint8 = 44
	TypeState                uint8 = 24
	TypeCHAPChallenge        uint8 = 60
	TypeEAPMessage           uint8 = 79
	TypeMessageAuthenticator uint8 = 80
	TypeErrorCause           uint8 = 101
)

// Code is the RADIUS Code octet. Values match RFC 2865/2866.
type Code uint8

const (
	AccessRequest      Code = 1
	AccessAccept       Code = 2
	AccessReject       Code = 3
	AccountingRequest  Code = 4
	AccountingResponse Code = 5
	AccessChallenge    Code = 11
	DisconnectRequest  Code = 40
	DisconnectACK      Code = 41
	DisconnectNAK      Code = 42
	CoARequest         Code = 43
	CoAACK             Code = 44
	CoANAK             Code = 45
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
	case AccessRequest, AccessAccept, AccessReject, AccountingRequest, AccountingResponse, AccessChallenge,
		DisconnectRequest, DisconnectACK, DisconnectNAK, CoARequest, CoAACK, CoANAK:
		return true
	default:
		return false
	}
}

// Advertised reports shipped Access/Accounting codes, including Challenge.
func (c Code) Advertised() bool {
	switch c {
	case AccessRequest, AccessAccept, AccessReject, AccountingRequest, AccountingResponse, AccessChallenge,
		DisconnectRequest, DisconnectACK, DisconnectNAK, CoARequest, CoAACK, CoANAK:
		return true
	default:
		return false
	}
}

// DynamicAuthFamily is RFC 5176 CoA/Disconnect.
func (c Code) DynamicAuthFamily() bool {
	switch c {
	case DisconnectRequest, DisconnectACK, DisconnectNAK, CoARequest, CoAACK, CoANAK:
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
	case DisconnectRequest:
		return "Disconnect-Request"
	case DisconnectACK:
		return "Disconnect-ACK"
	case DisconnectNAK:
		return "Disconnect-NAK"
	case CoARequest:
		return "CoA-Request"
	case CoAACK:
		return "CoA-ACK"
	case CoANAK:
		return "CoA-NAK"
	default:
		return "Code(" + strconv.Itoa(int(c)) + ")"
	}
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func put16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

package codec

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"

// Packet is one RADIUS datagram (RFC 2865 §3). Attributes are raw TLVs.
type Packet struct {
	Code          Code
	Identifier    uint8
	Authenticator [AuthenticatorSize]byte
	Attributes    attribute.RawSet
}

// Header is the 20-byte RADIUS header. Length is recorded only.
type Header struct {
	Code          Code
	Identifier    uint8
	Length        uint16
	Authenticator [AuthenticatorSize]byte
}

package attribute

import "strconv"

// Packet codes used for role legality. Values match RFC 2865/2866.
// This package does not import codec.
const (
	PacketAccessRequest      uint8 = 1
	PacketAccessAccept       uint8 = 2
	PacketAccessReject       uint8 = 3
	PacketAccountingRequest  uint8 = 4
	PacketAccountingResponse uint8 = 5
	// PacketAccessChallenge is recognized so role checks can reject it
	// cleanly. It is not an advertised MVP feature.
	PacketAccessChallenge uint8 = 11
)

// ValueKind is the RFC 2865 / RFC 3162 / RFC 2869 wire encoding.
type ValueKind string

const (
	KindText    ValueKind = "text"
	KindString  ValueKind = "string"
	KindInteger ValueKind = "integer"
	KindIPv4    ValueKind = "ipaddr"
	KindIPv6    ValueKind = "ipv6addr"
	KindTime    ValueKind = "time"
	KindVSA     ValueKind = "vsa"
	KindUnknown ValueKind = "unknown"
)

// Cardinality is how many instances of one key may appear.
type Cardinality string

const (
	CardinalitySingle Cardinality = "single"
	CardinalityMulti  Cardinality = "multi"
)

// Definition is immutable attribute metadata. It never carries a value.
type Definition struct {
	Name        string
	Vendor      uint32
	Code        uint8
	Kind        ValueKind
	Cardinality Cardinality
	Sensitivity Sensitivity
	MinOctets   int
	MaxOctets   int
	allowed     packetMask
	required    packetMask
	first       packetMask
}

// Key is the dictionary identity for this definition.
func (d Definition) Key() Key {
	if d.Vendor == 0 {
		return IETFKey(d.Code)
	}
	return Key{Vendor: d.Vendor, Code: uint32(d.Code), Space: SpaceVSA}
}

// AllowedIn reports whether the attribute may appear in packet.
func (d Definition) AllowedIn(packet uint8) bool { return d.allowed.has(packet) }

// RequiredIn reports whether a legal packet must include the attribute.
func (d Definition) RequiredIn(packet uint8) bool { return d.required.has(packet) }

// MustBeFirst reports whether the attribute must be the first TLV.
// Message-Authenticator is first on every Access and Accounting response.
func (d Definition) MustBeFirst(packet uint8) bool { return d.first.has(packet) }

// AllowedPackets returns allowed packet codes in numeric order.
func (d Definition) AllowedPackets() []uint8 { return d.allowed.codes() }

// String is name and code only. Definitions never hold values.
func (d Definition) String() string {
	return "radius.def{name=" + d.Name + " code=" + strconv.Itoa(int(d.Code)) + "}"
}

type packetMask uint16

const (
	bitAccessRequest packetMask = 1 << iota
	bitAccessAccept
	bitAccessReject
	bitAccountingRequest
	bitAccountingResponse
	bitAccessChallenge
)

func packetBit(code uint8) (packetMask, bool) {
	switch code {
	case PacketAccessRequest:
		return bitAccessRequest, true
	case PacketAccessAccept:
		return bitAccessAccept, true
	case PacketAccessReject:
		return bitAccessReject, true
	case PacketAccountingRequest:
		return bitAccountingRequest, true
	case PacketAccountingResponse:
		return bitAccountingResponse, true
	case PacketAccessChallenge:
		return bitAccessChallenge, true
	default:
		return 0, false
	}
}

func maskOf(codes ...uint8) packetMask {
	var m packetMask
	for _, c := range codes {
		b, ok := packetBit(c)
		if !ok {
			panic("radius dictionary: unknown packet code " + strconv.Itoa(int(c)))
		}
		m |= b
	}
	return m
}

func (m packetMask) has(code uint8) bool {
	b, ok := packetBit(code)
	return ok && m&b != 0
}

func (m packetMask) codes() []uint8 {
	all := [...]uint8{
		PacketAccessRequest,
		PacketAccessAccept,
		PacketAccessReject,
		PacketAccountingRequest,
		PacketAccountingResponse,
		PacketAccessChallenge,
	}
	out := make([]uint8, 0, 6)
	for _, c := range all {
		if m.has(c) {
			out = append(out, c)
		}
	}
	return out
}

func knownPacket(code uint8) bool {
	_, ok := packetBit(code)
	return ok
}

func requestPacket(code uint8) bool {
	return code == PacketAccessRequest || code == PacketAccountingRequest
}

func packetName(code uint8) string {
	switch code {
	case PacketAccessRequest:
		return "Access-Request"
	case PacketAccessAccept:
		return "Access-Accept"
	case PacketAccessReject:
		return "Access-Reject"
	case PacketAccountingRequest:
		return "Accounting-Request"
	case PacketAccountingResponse:
		return "Accounting-Response"
	case PacketAccessChallenge:
		return "Access-Challenge"
	default:
		return "Packet(" + strconv.Itoa(int(code)) + ")"
	}
}

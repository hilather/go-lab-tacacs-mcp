package attribute

// AttributeSpace identifies the attribute numbering space.
type AttributeSpace uint8

const (
	// SpaceIETF is RFC 2865 type codes (vendor 0).
	SpaceIETF AttributeSpace = 0
	// SpaceVSA is a vendor's nested attribute space (Cisco-AVPair, later MS-CHAP).
	SpaceVSA AttributeSpace = 1
)

// Key is a dictionary identity. Vendor is 0 for IETF attributes.
type Key struct {
	Vendor uint32
	Code   uint32
	Space  AttributeSpace
}

// IETFKey is the IETF (vendor 0) key for a Type octet.
func IETFKey(code uint8) Key {
	return Key{Vendor: 0, Code: uint32(code), Space: SpaceIETF}
}

package codec

import "github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"

const (
	HeaderSize        = 20
	AuthenticatorSize = 16
	MinPacketBytes    = 20
	MaxPacketBytes    = 4096
	DefaultMaxAttrs   = attribute.DefaultMaxAttributes
	DefaultMaxValues  = attribute.DefaultMaxValueBytes
)

// Bounds are lab decode/encode caps. Zero fields mean the RFC/lab defaults.
type Bounds struct {
	MaxPacketBytes int
	MaxAttributes  int
	MaxValueBytes  int
}

// DefaultBounds is 4096-byte packets, 256 attributes, 4096 value bytes.
func DefaultBounds() Bounds {
	return Bounds{
		MaxPacketBytes: MaxPacketBytes,
		MaxAttributes:  DefaultMaxAttrs,
		MaxValueBytes:  DefaultMaxValues,
	}
}

func (b Bounds) normalized() Bounds {
	if b.MaxPacketBytes <= 0 || b.MaxPacketBytes > MaxPacketBytes {
		b.MaxPacketBytes = MaxPacketBytes
	}
	if b.MaxPacketBytes < MinPacketBytes {
		b.MaxPacketBytes = MinPacketBytes
	}
	if b.MaxAttributes <= 0 {
		b.MaxAttributes = DefaultMaxAttrs
	}
	if b.MaxValueBytes <= 0 {
		b.MaxValueBytes = DefaultMaxValues
	}
	return b
}

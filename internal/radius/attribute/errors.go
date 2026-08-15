package attribute

import "errors"

var (
	ErrOverflow     = errors.New("radius attribute length overflows remaining payload")
	ErrLength       = errors.New("radius attribute length is less than 2")
	ErrTooMany      = errors.New("radius attribute count exceeds budget")
	ErrBudget       = errors.New("radius attribute value bytes exceed budget")
	ErrValueTooLong = errors.New("radius attribute value exceeds 253 bytes")
	ErrNotVSA       = errors.New("radius attribute is not Vendor-Specific")
	ErrVSAShort     = errors.New("radius Vendor-Specific value is shorter than a vendor id")
	ErrVSAValueLong = errors.New("radius Vendor-Specific payload exceeds attribute value budget")

	ErrUnknownPacket   = errors.New("radius attribute role check: unknown packet code")
	ErrIllegalRole     = errors.New("radius attribute is not legal in this packet")
	ErrCardinality     = errors.New("radius attribute exceeds dictionary cardinality")
	ErrMissingRequired = errors.New("radius packet is missing a required attribute")
	ErrNotFirst        = errors.New("radius attribute must be first in this packet")
	ErrValueLength     = errors.New("radius attribute value length is illegal for its type")
)

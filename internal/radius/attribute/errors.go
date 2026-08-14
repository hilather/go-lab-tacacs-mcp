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
)

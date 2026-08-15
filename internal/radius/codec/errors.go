package codec

import (
	"errors"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
)

var (
	ErrHeaderShort    = errors.New("radius packet shorter than 20 bytes")
	ErrInvalidLength  = errors.New("radius declared length is invalid")
	ErrPacketTooLarge = errors.New("radius encoded packet exceeds maximum length")

	ErrAttributeOverflow = attribute.ErrOverflow
	ErrAttributeLength   = attribute.ErrLength
	ErrTooManyAttributes = attribute.ErrTooMany
	ErrAttributeBudget   = attribute.ErrBudget
	ErrAttributeValue    = attribute.ErrValueTooLong
)

// Frozen silent-discard reasons (design §5.7). Role-invalid codes are
// classified by the caller; the codec does not discard unknown codes.
const (
	ReasonMalformedHeader = "discard_malformed_header"
	ReasonInvalidLength   = "discard_invalid_length"
	ReasonInvalidCode     = "discard_invalid_code"
)

// DiscardReason maps a codec error to a §5.7 reason, or empty if err is nil.
func DiscardReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrHeaderShort):
		return ReasonMalformedHeader
	case errors.Is(err, ErrInvalidLength),
		errors.Is(err, ErrPacketTooLarge),
		errors.Is(err, ErrAttributeOverflow),
		errors.Is(err, ErrAttributeLength),
		errors.Is(err, ErrTooManyAttributes),
		errors.Is(err, ErrAttributeBudget),
		errors.Is(err, ErrAttributeValue):
		return ReasonInvalidLength
	default:
		return ReasonMalformedHeader
	}
}

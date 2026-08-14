package attribute

// IETF attribute type numbers used for framing and redaction.
// Named dictionary metadata is a later change (RAD-CODEC-004).
const (
	TypeUserName             uint8 = 1
	TypeUserPassword         uint8 = 2
	TypeCHAPPassword         uint8 = 3
	TypeVendorSpecific       uint8 = 26
	TypeProxyState           uint8 = 33
	TypeMessageAuthenticator uint8 = 80
)

// MaxValueLength is the maximum Value size (Length is one octet and includes Type+Length).
const MaxValueLength = 253

// DefaultMaxAttributes is the default decoded attribute count cap.
const DefaultMaxAttributes = 256

// DefaultMaxValueBytes is the default sum of attribute Value bytes.
const DefaultMaxValueBytes = 4096

// Sensitive reports types whose values must never appear in logs or errors.
func Sensitive(typ uint8) bool {
	switch typ {
	case TypeUserPassword, TypeCHAPPassword, TypeMessageAuthenticator:
		return true
	default:
		return false
	}
}

package codec

import "errors"

var (
	ErrHeaderShort   = errors.New("radius testclient: packet shorter than 20 bytes")
	ErrInvalidLength = errors.New("radius testclient: declared length is invalid")
	ErrPacketTooBig  = errors.New("radius testclient: encoded packet exceeds 4096 bytes")

	ErrAttrOverflow  = errors.New("radius testclient: attribute length overflows remaining payload")
	ErrAttrLength    = errors.New("radius testclient: attribute length is less than 2")
	ErrTooManyAttrs  = errors.New("radius testclient: attribute count exceeds budget")
	ErrAttrBudget    = errors.New("radius testclient: attribute value bytes exceed budget")
	ErrAttrValueLong = errors.New("radius testclient: attribute value exceeds 253 bytes")

	ErrNotVSA             = errors.New("radius testclient: attribute is not Vendor-Specific")
	ErrVSAShort           = errors.New("radius testclient: Vendor-Specific value is shorter than a vendor id")
	ErrVSAValueLong       = errors.New("radius testclient: Vendor-Specific payload exceeds attribute value budget")
	ErrVendorTLVMalformed = errors.New("radius testclient: vendor TLV is malformed")

	ErrEmptySecret     = errors.New("radius testclient: shared secret is empty")
	ErrPasswordTooLong = errors.New("radius testclient: User-Password exceeds 128 octets")
	ErrHiddenPassword  = errors.New("radius testclient: User-Password hidden value is invalid")

	ErrMissingMA   = errors.New("radius testclient: Message-Authenticator is missing")
	ErrDuplicateMA = errors.New("radius testclient: more than one Message-Authenticator")
	ErrInvalidMA   = errors.New("radius testclient: Message-Authenticator is invalid")

	ErrInvalidAcctAuth = errors.New("radius testclient: Accounting-Request Authenticator is invalid")
	ErrInvalidRespAuth = errors.New("radius testclient: Response Authenticator is invalid")
)

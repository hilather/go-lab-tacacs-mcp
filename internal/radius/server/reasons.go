package server

// Frozen silent-discard and reject reasons (design §5.7).
const (
	ReasonUnknownClient     = "discard_unknown_client"
	ReasonAmbiguousClient   = "discard_ambiguous_client"
	ReasonMalformedHeader   = "discard_malformed_header"
	ReasonInvalidLength     = "discard_invalid_length"
	ReasonInvalidCode       = "discard_invalid_code"
	ReasonInvalidAcctAuth   = "discard_invalid_accounting_request_authenticator"
	ReasonOverload          = "drop_overload"
	ReasonUnsupportedMethod = "reject_unsupported_method"
	ReasonOK                = "ok"
)

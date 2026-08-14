package server

// Frozen silent-discard and reject reasons (design §5.7).
const (
	ReasonUnknownClient     = "discard_unknown_client"
	ReasonAmbiguousClient   = "discard_ambiguous_client"
	ReasonMalformedHeader   = "discard_malformed_header"
	ReasonInvalidLength     = "discard_invalid_length"
	ReasonInvalidCode       = "discard_invalid_code"
	ReasonInvalidAcctAuth   = "discard_invalid_accounting_request_authenticator"
	ReasonInvalidMA         = "discard_invalid_message_authenticator"
	ReasonUnknownAcctStatus = "discard_unknown_acct_status"
	ReasonAmbiguousIdentity = "ambiguous_identity"
	ReasonOverload          = "drop_overload"
	ReasonUnsupportedMethod = "reject_unsupported_method"
	ReasonInternal          = "internal_error"
	ReasonOK                = "ok"
)

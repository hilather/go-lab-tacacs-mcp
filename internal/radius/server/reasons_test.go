package server

import "testing"

func TestReasonTableStable(t *testing.T) {
	t.Parallel()
	// Frozen design §5.7 reason_code strings. Changing a value is a
	// protocol/metrics contract break.
	want := map[string]string{
		"unknown_client":         ReasonUnknownClient,
		"ambiguous_client":       ReasonAmbiguousClient,
		"malformed_header":       ReasonMalformedHeader,
		"invalid_length":         ReasonInvalidLength,
		"invalid_code":           ReasonInvalidCode,
		"invalid_acct_auth":      ReasonInvalidAcctAuth,
		"invalid_ma":             ReasonInvalidMA,
		"missing_ma":             ReasonMissingMA,
		"eap_without_ma":         ReasonEAPWithoutMA,
		"proxy_state_without_ma": ReasonProxyStateWithoutMA,
		"unknown_acct_status":    ReasonUnknownAcctStatus,
		"ambiguous_identity":     ReasonAmbiguousIdentity,
		"overload":               ReasonOverload,
		"missing_username":       ReasonMissingUsername,
		"conflicting_auth":       ReasonConflictingAuth,
		"chap_password_length":   ReasonCHAPPasswordLength,
		"unsupported_method":     ReasonUnsupportedMethod,
		"bad_credentials":        ReasonBadCredentials,
		"password_change":        ReasonPasswordChangeRequired,
		"policy":                 ReasonPolicy,
		"internal":               ReasonInternal,
		"ok":                     ReasonOK,
	}
	locked := map[string]string{
		"unknown_client":         "discard_unknown_client",
		"ambiguous_client":       "discard_ambiguous_client",
		"malformed_header":       "discard_malformed_header",
		"invalid_length":         "discard_invalid_length",
		"invalid_code":           "discard_invalid_code",
		"invalid_acct_auth":      "discard_invalid_accounting_request_authenticator",
		"invalid_ma":             "discard_invalid_message_authenticator",
		"missing_ma":             "discard_missing_message_authenticator",
		"eap_without_ma":         "discard_eap_without_ma",
		"proxy_state_without_ma": "discard_proxy_state_without_ma",
		"unknown_acct_status":    "discard_unknown_acct_status",
		"ambiguous_identity":     "ambiguous_identity",
		"overload":               "drop_overload",
		"missing_username":       "reject_missing_username",
		"conflicting_auth":       "reject_conflicting_auth",
		"chap_password_length":   "reject_chap_password_length",
		"unsupported_method":     "reject_unsupported_method",
		"bad_credentials":        "reject_bad_credentials",
		"password_change":        "reject_password_change_required",
		"policy":                 "reject_policy",
		"internal":               "internal_error",
		"ok":                     "ok",
	}
	if len(want) != len(locked) {
		t.Fatalf("table size %d != %d", len(want), len(locked))
	}
	for k, got := range want {
		if got != locked[k] {
			t.Errorf("%s: %q != %q", k, got, locked[k])
		}
	}
}

package domain

import "strings"

// AuthMethod is a protocol-neutral credential method used by aaa and policy/radius.
// It is not TACACS AuthenType or AuthenMethod.
// Config/API "pap" is an accepted alias; the stored value is always "password".
type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "password"
	AuthMethodCHAP     AuthMethod = "chap"
	AuthMethodMSCHAPv1 AuthMethod = "mschapv1"
	AuthMethodMSCHAPv2 AuthMethod = "mschapv2"
	AuthMethodEAP      AuthMethod = "eap"
)

func (m AuthMethod) Valid() bool {
	switch m {
	case AuthMethodPassword, AuthMethodCHAP, AuthMethodMSCHAPv1, AuthMethodMSCHAPv2, AuthMethodEAP:
		return true
	default:
		return false
	}
}

func (m AuthMethod) String() string { return string(m) }

// ParseAuthMethod accepts password (canonical), pap (alias of password), chap,
// mschapv1, mschapv2, or eap. Unknown tokens including passwd fail. The returned
// value is never "pap".
func ParseAuthMethod(s string) (AuthMethod, error) {
	switch strings.ToLower(s) {
	case "password", "pap":
		return AuthMethodPassword, nil
	case "chap":
		return AuthMethodCHAP, nil
	case "mschapv1":
		return AuthMethodMSCHAPv1, nil
	case "mschapv2":
		return AuthMethodMSCHAPv2, nil
	case "eap":
		return AuthMethodEAP, nil
	default:
		return "", NewError(CodeInvalidArgument, "authentication method must be password, pap, chap, mschapv1, mschapv2, or eap")
	}
}

// Effect is a protocol-neutral authorization result used by policy/radius.
// It is not TACACS AuthorDecision.
type Effect string

const (
	EffectPermit Effect = "permit"
	EffectDeny   Effect = "deny"
	EffectError  Effect = "error"
)

func (e Effect) Valid() bool {
	switch e {
	case EffectPermit, EffectDeny, EffectError:
		return true
	default:
		return false
	}
}

func (e Effect) String() string { return string(e) }

// ParseEffect accepts permit, deny, or error only.
func ParseEffect(s string) (Effect, error) {
	e := Effect(strings.ToLower(s))
	if !e.Valid() {
		return "", NewError(CodeInvalidArgument, "effect must be permit, deny, or error")
	}
	return e, nil
}

// AuthOutcome is a protocol-neutral authentication result.
// It is not TACACS AuthenStatus.
type AuthOutcome string

const (
	AuthPass      AuthOutcome = "pass"
	AuthReject    AuthOutcome = "reject"
	AuthChallenge AuthOutcome = "challenge" // reserved
	AuthError     AuthOutcome = "error"
)

func (o AuthOutcome) Valid() bool {
	switch o {
	case AuthPass, AuthReject, AuthChallenge, AuthError:
		return true
	default:
		return false
	}
}

func (o AuthOutcome) String() string { return string(o) }

// ParseAuthOutcome accepts pass, reject, challenge, or error only.
func ParseAuthOutcome(s string) (AuthOutcome, error) {
	o := AuthOutcome(strings.ToLower(s))
	if !o.Valid() {
		return "", NewError(CodeInvalidArgument, "authentication outcome must be pass, reject, challenge, or error")
	}
	return o, nil
}

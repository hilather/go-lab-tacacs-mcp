package domain

import "strings"

// AuthenType is a TACACS+ authentication type (RFC 8907 §5.4.2).
// Unknown wire values are stored as-is and are not Valid.
type AuthenType uint8

const (
	AuthenTypeASCII    AuthenType = 0x01
	AuthenTypePAP      AuthenType = 0x02
	AuthenTypeCHAP     AuthenType = 0x03
	AuthenTypeARAP     AuthenType = 0x04
	AuthenTypeMSCHAP   AuthenType = 0x05
	AuthenTypeMSCHAPV2 AuthenType = 0x06
)

func (t AuthenType) Valid() bool {
	switch t {
	case AuthenTypeASCII, AuthenTypePAP, AuthenTypeCHAP, AuthenTypeARAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPV2:
		return true
	default:
		return false
	}
}

func (t AuthenType) String() string {
	switch t {
	case AuthenTypeASCII:
		return "ascii"
	case AuthenTypePAP:
		return "pap"
	case AuthenTypeCHAP:
		return "chap"
	case AuthenTypeARAP:
		return "arap"
	case AuthenTypeMSCHAP:
		return "mschap"
	case AuthenTypeMSCHAPV2:
		return "mschapv2"
	default:
		return ""
	}
}

// ParseAuthenType accepts canonical names only. Numeric and unknown strings fail.
func ParseAuthenType(s string) (AuthenType, error) {
	switch strings.ToLower(s) {
	case "ascii":
		return AuthenTypeASCII, nil
	case "pap":
		return AuthenTypePAP, nil
	case "chap":
		return AuthenTypeCHAP, nil
	case "arap":
		return AuthenTypeARAP, nil
	case "mschap", "mschapv1":
		return AuthenTypeMSCHAP, nil
	case "mschapv2":
		return AuthenTypeMSCHAPV2, nil
	default:
		return 0, NewError(CodeInvalidArgument, "unknown authentication type")
	}
}

// AuthenService is a TACACS+ authentication service (RFC 8907 §5.4.1).
type AuthenService uint8

const (
	AuthenServiceNone    AuthenService = 0x00
	AuthenServiceLogin   AuthenService = 0x01
	AuthenServiceEnable  AuthenService = 0x02
	AuthenServicePPP     AuthenService = 0x03
	AuthenServiceARAP    AuthenService = 0x04
	AuthenServicePT      AuthenService = 0x05
	AuthenServiceRCMD    AuthenService = 0x06
	AuthenServiceX25     AuthenService = 0x07
	AuthenServiceNASI    AuthenService = 0x08
	AuthenServiceFWProxy AuthenService = 0x09
)

func (s AuthenService) Valid() bool {
	switch s {
	case AuthenServiceNone, AuthenServiceLogin, AuthenServiceEnable, AuthenServicePPP,
		AuthenServiceARAP, AuthenServicePT, AuthenServiceRCMD, AuthenServiceX25,
		AuthenServiceNASI, AuthenServiceFWProxy:
		return true
	default:
		return false
	}
}

func (s AuthenService) String() string {
	switch s {
	case AuthenServiceNone:
		return "none"
	case AuthenServiceLogin:
		return "login"
	case AuthenServiceEnable:
		return "enable"
	case AuthenServicePPP:
		return "ppp"
	case AuthenServiceARAP:
		return "arap"
	case AuthenServicePT:
		return "pt"
	case AuthenServiceRCMD:
		return "rcmd"
	case AuthenServiceX25:
		return "x25"
	case AuthenServiceNASI:
		return "nasi"
	case AuthenServiceFWProxy:
		return "fwproxy"
	default:
		return ""
	}
}

// ParseAuthenService accepts canonical names only.
func ParseAuthenService(s string) (AuthenService, error) {
	switch strings.ToLower(s) {
	case "none":
		return AuthenServiceNone, nil
	case "login":
		return AuthenServiceLogin, nil
	case "enable":
		return AuthenServiceEnable, nil
	case "ppp":
		return AuthenServicePPP, nil
	case "arap":
		return AuthenServiceARAP, nil
	case "pt":
		return AuthenServicePT, nil
	case "rcmd":
		return AuthenServiceRCMD, nil
	case "x25":
		return AuthenServiceX25, nil
	case "nasi":
		return AuthenServiceNASI, nil
	case "fwproxy":
		return AuthenServiceFWProxy, nil
	default:
		return 0, NewError(CodeInvalidArgument, "unknown authentication service")
	}
}

// AuthenAction is a TACACS+ authentication action.
type AuthenAction uint8

const (
	AuthenActionLogin    AuthenAction = 0x01
	AuthenActionCHPASS   AuthenAction = 0x02
	AuthenActionSendPass AuthenAction = 0x03 // removed from RFC 8907; recognized to reject
	AuthenActionSendAuth AuthenAction = 0x04
)

func (a AuthenAction) Valid() bool {
	switch a {
	case AuthenActionLogin, AuthenActionCHPASS, AuthenActionSendPass, AuthenActionSendAuth:
		return true
	default:
		return false
	}
}

func (a AuthenAction) String() string {
	switch a {
	case AuthenActionLogin:
		return "login"
	case AuthenActionCHPASS:
		return "chpass"
	case AuthenActionSendPass:
		return "sendpass"
	case AuthenActionSendAuth:
		return "sendauth"
	default:
		return ""
	}
}

// ParseAuthenAction accepts canonical names only.
func ParseAuthenAction(s string) (AuthenAction, error) {
	switch strings.ToLower(s) {
	case "login":
		return AuthenActionLogin, nil
	case "chpass":
		return AuthenActionCHPASS, nil
	case "sendpass":
		return AuthenActionSendPass, nil
	case "sendauth":
		return AuthenActionSendAuth, nil
	default:
		return 0, NewError(CodeInvalidArgument, "unknown authentication action")
	}
}

// AuthenStatus is a TACACS+ authentication reply status.
type AuthenStatus uint8

const (
	AuthenStatusPass    AuthenStatus = 0x01
	AuthenStatusFail    AuthenStatus = 0x02
	AuthenStatusGetData AuthenStatus = 0x03
	AuthenStatusGetUser AuthenStatus = 0x04
	AuthenStatusGetPass AuthenStatus = 0x05
	AuthenStatusRestart AuthenStatus = 0x06
	AuthenStatusError   AuthenStatus = 0x07
	AuthenStatusFollow  AuthenStatus = 0x21
)

func (s AuthenStatus) Valid() bool {
	switch s {
	case AuthenStatusPass, AuthenStatusFail, AuthenStatusGetData, AuthenStatusGetUser,
		AuthenStatusGetPass, AuthenStatusRestart, AuthenStatusError, AuthenStatusFollow:
		return true
	default:
		return false
	}
}

func (s AuthenStatus) String() string {
	switch s {
	case AuthenStatusPass:
		return "pass"
	case AuthenStatusFail:
		return "fail"
	case AuthenStatusGetData:
		return "getdata"
	case AuthenStatusGetUser:
		return "getuser"
	case AuthenStatusGetPass:
		return "getpass"
	case AuthenStatusRestart:
		return "restart"
	case AuthenStatusError:
		return "error"
	case AuthenStatusFollow:
		return "follow"
	default:
		return ""
	}
}

// ParseAuthenStatus accepts canonical names only.
func ParseAuthenStatus(s string) (AuthenStatus, error) {
	switch strings.ToLower(s) {
	case "pass":
		return AuthenStatusPass, nil
	case "fail":
		return AuthenStatusFail, nil
	case "getdata":
		return AuthenStatusGetData, nil
	case "getuser":
		return AuthenStatusGetUser, nil
	case "getpass":
		return AuthenStatusGetPass, nil
	case "restart":
		return AuthenStatusRestart, nil
	case "error":
		return AuthenStatusError, nil
	case "follow":
		return AuthenStatusFollow, nil
	default:
		return 0, NewError(CodeInvalidArgument, "unknown authentication status")
	}
}

// RuleKind selects which first-match evaluator a compiled rule belongs to.
// Service and command rules are never mixed in one list.
type RuleKind string

const (
	RuleKindService RuleKind = "service"
	RuleKindCommand RuleKind = "command"
)

func (k RuleKind) Valid() bool {
	switch k {
	case RuleKindService, RuleKindCommand:
		return true
	default:
		return false
	}
}

func (k RuleKind) String() string { return string(k) }

// ParseRuleKind accepts service or command only.
func ParseRuleKind(s string) (RuleKind, error) {
	k := RuleKind(strings.ToLower(s))
	if !k.Valid() {
		return "", NewError(CodeInvalidArgument, "rule kind must be service or command")
	}
	return k, nil
}

// AuthorDecision is the domain authorization result:
// permit_add, permit_replace, or deny.
type AuthorDecision string

const (
	DecisionPermitAdd     AuthorDecision = "permit_add"
	DecisionPermitReplace AuthorDecision = "permit_replace"
	DecisionDeny          AuthorDecision = "deny"
)

func (d AuthorDecision) Valid() bool {
	switch d {
	case DecisionPermitAdd, DecisionPermitReplace, DecisionDeny:
		return true
	default:
		return false
	}
}

func (d AuthorDecision) String() string { return string(d) }

// ParseAuthorDecision accepts permit_add, permit_replace, or deny.
func ParseAuthorDecision(s string) (AuthorDecision, error) {
	d := AuthorDecision(strings.ToLower(s))
	if !d.Valid() {
		return "", NewError(CodeInvalidArgument, "authorization decision must be permit_add, permit_replace, or deny")
	}
	return d, nil
}

// AuthorStatus is the TACACS+ authorization reply status.
type AuthorStatus uint8

const (
	AuthorStatusPassAdd  AuthorStatus = 0x01
	AuthorStatusPassRepl AuthorStatus = 0x02
	AuthorStatusFail     AuthorStatus = 0x10
	AuthorStatusError    AuthorStatus = 0x11
	AuthorStatusFollow   AuthorStatus = 0x21
)

func (s AuthorStatus) Valid() bool {
	switch s {
	case AuthorStatusPassAdd, AuthorStatusPassRepl, AuthorStatusFail, AuthorStatusError, AuthorStatusFollow:
		return true
	default:
		return false
	}
}

func (s AuthorStatus) String() string {
	switch s {
	case AuthorStatusPassAdd:
		return "pass_add"
	case AuthorStatusPassRepl:
		return "pass_repl"
	case AuthorStatusFail:
		return "fail"
	case AuthorStatusError:
		return "error"
	case AuthorStatusFollow:
		return "follow"
	default:
		return ""
	}
}

// WireStatus maps a domain decision to the TACACS+ authorization status.
func (d AuthorDecision) WireStatus() AuthorStatus {
	switch d {
	case DecisionPermitAdd:
		return AuthorStatusPassAdd
	case DecisionPermitReplace:
		return AuthorStatusPassRepl
	case DecisionDeny:
		return AuthorStatusFail
	default:
		return AuthorStatusError
	}
}

// AcctFlags is the TACACS+ accounting flags byte.
type AcctFlags uint8

const (
	AcctFlagStart           AcctFlags = 0x02
	AcctFlagStop            AcctFlags = 0x04
	AcctFlagWatchdog        AcctFlags = 0x08
	AcctFlagsWatchdogUpdate AcctFlags = 0x0a
)

func (f AcctFlags) Valid() bool {
	switch f {
	case AcctFlagStart, AcctFlagStop, AcctFlagWatchdog, AcctFlagsWatchdogUpdate:
		return true
	default:
		return false
	}
}

func (f AcctFlags) String() string {
	switch f {
	case AcctFlagStart:
		return "start"
	case AcctFlagStop:
		return "stop"
	case AcctFlagWatchdog:
		return "watchdog"
	case AcctFlagsWatchdogUpdate:
		return "watchdog_update"
	default:
		return ""
	}
}

// ParseAcctFlags accepts canonical names only.
func ParseAcctFlags(s string) (AcctFlags, error) {
	switch strings.ToLower(s) {
	case "start":
		return AcctFlagStart, nil
	case "stop":
		return AcctFlagStop, nil
	case "watchdog":
		return AcctFlagWatchdog, nil
	case "watchdog_update":
		return AcctFlagsWatchdogUpdate, nil
	default:
		return 0, NewError(CodeInvalidArgument, "unknown accounting flags")
	}
}

// AcctStatus is the TACACS+ accounting reply status.
type AcctStatus uint8

const (
	AcctStatusSuccess AcctStatus = 0x01
	AcctStatusError   AcctStatus = 0x02
	AcctStatusFollow  AcctStatus = 0x21
)

func (s AcctStatus) Valid() bool {
	switch s {
	case AcctStatusSuccess, AcctStatusError, AcctStatusFollow:
		return true
	default:
		return false
	}
}

func (s AcctStatus) String() string {
	switch s {
	case AcctStatusSuccess:
		return "success"
	case AcctStatusError:
		return "error"
	case AcctStatusFollow:
		return "follow"
	default:
		return ""
	}
}

// PacketFamily is the TACACS+ header type.
type PacketFamily uint8

const (
	PacketAuthen PacketFamily = 0x01
	PacketAuthor PacketFamily = 0x02
	PacketAcct   PacketFamily = 0x03
)

func (p PacketFamily) Valid() bool {
	switch p {
	case PacketAuthen, PacketAuthor, PacketAcct:
		return true
	default:
		return false
	}
}

func (p PacketFamily) String() string {
	switch p {
	case PacketAuthen:
		return "authen"
	case PacketAuthor:
		return "author"
	case PacketAcct:
		return "acct"
	default:
		return ""
	}
}

// Transport is a TACACS+ listener kind.
type Transport string

const (
	TransportLegacy Transport = "legacy"
	TransportTLS    Transport = "tls"
)

func (t Transport) Valid() bool {
	switch t {
	case TransportLegacy, TransportTLS:
		return true
	default:
		return false
	}
}

func (t Transport) String() string { return string(t) }

// ParseTransport accepts legacy or tls only.
func ParseTransport(s string) (Transport, error) {
	t := Transport(strings.ToLower(s))
	if !t.Valid() {
		return "", NewError(CodeInvalidArgument, "transport must be legacy or tls")
	}
	return t, nil
}

// MatchMode is a client identity selector.
type MatchMode string

const (
	MatchAddressAndCertificate MatchMode = "address_and_certificate"
	MatchCertificateOnly       MatchMode = "certificate_only"
)

func (m MatchMode) Valid() bool {
	switch m {
	case MatchAddressAndCertificate, MatchCertificateOnly:
		return true
	default:
		return false
	}
}

func (m MatchMode) String() string { return string(m) }

// ParseMatchMode accepts the two compiled match modes.
func ParseMatchMode(s string) (MatchMode, error) {
	m := MatchMode(strings.ToLower(s))
	if !m.Valid() {
		return "", NewError(CodeInvalidArgument, "match mode must be address_and_certificate or certificate_only")
	}
	return m, nil
}

// PrivilegeLevel is a TACACS+ priv-lvl (0 through 15).
type PrivilegeLevel uint8

const (
	PrivilegeMin PrivilegeLevel = 0
	PrivilegeMax PrivilegeLevel = 15
)

func (p PrivilegeLevel) Valid() bool { return p <= PrivilegeMax }

// ParsePrivilegeLevel rejects values outside 0-15.
func ParsePrivilegeLevel(v int) (PrivilegeLevel, error) {
	if v < int(PrivilegeMin) || v > int(PrivilegeMax) {
		return 0, NewError(CodeInvalidArgument, "privilege level must be 0-15")
	}
	return PrivilegeLevel(v), nil
}

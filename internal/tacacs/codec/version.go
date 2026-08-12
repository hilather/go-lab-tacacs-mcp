package codec

// Flow is a recognized authentication conversation the codec can name.
type Flow byte

const (
	FlowNone Flow = iota
	FlowASCIILogin
	FlowPAPLogin
	FlowCHAPLogin
	FlowMSCHAPv1
	FlowMSCHAPv2
	FlowEnable
	FlowASCIIChpass
)

// Disposition is the version/action/type/service matrix result.
type Disposition byte

const (
	DispositionAccept Disposition = iota
	DispositionFail
	DispositionError
)

// AuthenStatus maps a matrix disposition to a REPLY status.
// Accept has no implied terminal status (the AAA conversation continues).
func (d Disposition) AuthenStatus() byte {
	switch d {
	case DispositionFail:
		return AuthenStatusFail
	case DispositionError:
		return AuthenStatusError
	default:
		return 0
	}
}

// KnownAuthenService reports whether service is an RFC-defined code, including NONE.
func KnownAuthenService(service byte) bool {
	switch service {
	case AuthenServiceNone, AuthenServiceLogin, AuthenServiceEnable, AuthenServicePPP,
		AuthenServicePT, AuthenServiceRCMD, AuthenServiceX25,
		AuthenServiceNASI, AuthenServiceFWProxy:
		return true
	default:
		return false
	}
}

// ClassifyAuthenStart applies the version × action × type × service matrix.
// LOGIN + service=ENABLE ignores authen_type and requires minor 0.
func ClassifyAuthenStart(minor byte, s AuthenStart) (Flow, Disposition) {
	switch s.Action {
	case AuthenActionSendAuth, AuthenActionSendPass:
		return FlowNone, DispositionError
	case AuthenActionCHPASS:
		return classifyCHPASS(minor, s)
	case AuthenActionLogin:
		return classifyLogin(minor, s)
	default:
		return FlowNone, DispositionError
	}
}

func classifyCHPASS(minor byte, s AuthenStart) (Flow, Disposition) {
	if s.Service == AuthenServiceEnable {
		return FlowNone, DispositionFail
	}
	if s.Type != AuthenTypeASCII {
		return FlowNone, DispositionError
	}
	if s.Service == AuthenServiceNone || !KnownAuthenService(s.Service) {
		return FlowASCIIChpass, DispositionFail
	}
	if minor != 0 {
		return FlowASCIIChpass, DispositionFail
	}
	return FlowASCIIChpass, DispositionAccept
}

func classifyLogin(minor byte, s AuthenStart) (Flow, Disposition) {
	if s.Service == AuthenServiceEnable {
		// Type is unused (RFC 8907 §5.4.2.6).
		if minor != 0 {
			return FlowEnable, DispositionFail
		}
		return FlowEnable, DispositionAccept
	}

	flow, ok := loginFlow(s.Type)
	if !ok {
		return FlowNone, DispositionError
	}
	if s.Service == AuthenServiceNone || !KnownAuthenService(s.Service) {
		return flow, DispositionFail
	}
	want := byte(0)
	if flow != FlowASCIILogin {
		want = 1
	}
	if minor != want {
		return flow, DispositionFail
	}
	return flow, DispositionAccept
}

func loginFlow(typ byte) (Flow, bool) {
	switch typ {
	case AuthenTypeASCII:
		return FlowASCIILogin, true
	case AuthenTypePAP:
		return FlowPAPLogin, true
	case AuthenTypeCHAP:
		return FlowCHAPLogin, true
	case AuthenTypeMSCHAP:
		return FlowMSCHAPv1, true
	case AuthenTypeMSCHAPV2:
		return FlowMSCHAPv2, true
	default:
		return FlowNone, false
	}
}

// ClassifyPacketMinor returns the family-level minor-version disposition.
// AUTHEN uses ClassifyAuthenStart instead (minor depends on action and type).
func ClassifyPacketMinor(typ, minor byte) Disposition {
	switch typ {
	case TypeAuthor, TypeAcct:
		if minor != 0 {
			return DispositionError
		}
		return DispositionAccept
	case TypeAuthen:
		if minor > 1 {
			return DispositionFail
		}
		return DispositionAccept
	default:
		return DispositionError
	}
}

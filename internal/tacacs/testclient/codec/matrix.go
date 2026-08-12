package codec

// Kind names the authentication conversation selected by the matrix.
type Kind byte

const (
	KindNone Kind = iota
	KindASCII
	KindPAP
	KindCHAP
	KindMS1
	KindMS2
	KindEnable
	KindChpass
)

// Verdict is accept / FAIL / ERROR for the version matrix.
type Verdict byte

const (
	OK Verdict = iota
	Fail
	Error
)

func knownSvc(s byte) bool {
	switch s {
	case SvcNone, SvcLogin, SvcEnable, SvcPPP, SvcPT, SvcRCMD, SvcX25, SvcNASI, SvcFWProxy:
		return true
	default:
		return false
	}
}

func loginKind(t byte) (Kind, bool) {
	switch t {
	case TypeASCII:
		return KindASCII, true
	case TypePAP:
		return KindPAP, true
	case TypeCHAP:
		return KindCHAP, true
	case TypeMSCHAP:
		return KindMS1, true
	case TypeMSCHAPV2:
		return KindMS2, true
	default:
		return KindNone, false
	}
}

// ScoreStart applies the version × action × type × service table.
// ENABLE LOGIN ignores AType.
func ScoreStart(minor byte, st Start) (Kind, Verdict) {
	switch st.Action {
	case ActionSendAuth, ActionSendPass:
		return KindNone, Error
	case ActionCHPASS:
		if st.Service == SvcEnable {
			return KindNone, Fail
		}
		if st.AType != TypeASCII {
			return KindNone, Error
		}
		if st.Service == SvcNone || !knownSvc(st.Service) {
			return KindChpass, Fail
		}
		if minor != 0 {
			return KindChpass, Fail
		}
		return KindChpass, OK
	case ActionLogin:
		if st.Service == SvcEnable {
			if minor != 0 {
				return KindEnable, Fail
			}
			return KindEnable, OK
		}
		k, ok := loginKind(st.AType)
		if !ok {
			return KindNone, Error
		}
		if st.Service == SvcNone || !knownSvc(st.Service) {
			return k, Fail
		}
		need := byte(0)
		if k != KindASCII {
			need = 1
		}
		if minor != need {
			return k, Fail
		}
		return k, OK
	default:
		return KindNone, Error
	}
}

func FamilyMinor(typ, minor byte) Verdict {
	switch typ {
	case TypeAuthor, TypeAcct:
		if minor != 0 {
			return Error
		}
		return OK
	case TypeAuthen:
		if minor > 1 {
			return Fail
		}
		return OK
	default:
		return Error
	}
}

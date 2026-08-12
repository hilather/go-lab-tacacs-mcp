package codec

// RFC 8907 authentication, authorization, and accounting wire values.
const (
	AuthenActionLogin    = 0x01
	AuthenActionCHPASS   = 0x02
	AuthenActionSendPass = 0x03 // removed; recognized so it can be rejected
	AuthenActionSendAuth = 0x04

	AuthenTypeNotSet   = 0x00
	AuthenTypeASCII    = 0x01
	AuthenTypePAP      = 0x02
	AuthenTypeCHAP     = 0x03
	AuthenTypeARAP     = 0x04
	AuthenTypeMSCHAP   = 0x05
	AuthenTypeMSCHAPV2 = 0x06

	AuthenServiceNone   = 0x00
	AuthenServiceLogin  = 0x01
	AuthenServiceEnable = 0x02
	AuthenServicePPP    = 0x03
	// AuthenServiceARAP is the removed Draft service 0x04. RFC 8907 does not list it.
	AuthenServiceARAP    = 0x04
	AuthenServicePT      = 0x05
	AuthenServiceRCMD    = 0x06
	AuthenServiceX25     = 0x07
	AuthenServiceNASI    = 0x08
	AuthenServiceFWProxy = 0x09

	AuthenStatusPass    = 0x01
	AuthenStatusFail    = 0x02
	AuthenStatusGetData = 0x03
	AuthenStatusGetUser = 0x04
	AuthenStatusGetPass = 0x05
	AuthenStatusRestart = 0x06
	AuthenStatusError   = 0x07
	AuthenStatusFollow  = 0x21

	ContinueFlagAbort     = 0x01
	ContinueFlagKnownMask = ContinueFlagAbort

	ReplyFlagNoEcho    = 0x01
	ReplyFlagKnownMask = ReplyFlagNoEcho

	AuthorStatusPassAdd  = 0x01
	AuthorStatusPassRepl = 0x02
	AuthorStatusFail     = 0x10
	AuthorStatusError    = 0x11
	AuthorStatusFollow   = 0x21

	AcctFlagStart          = 0x02
	AcctFlagStop           = 0x04
	AcctFlagWatchdog       = 0x08
	AcctFlagWatchdogUpdate = 0x0a

	AcctStatusSuccess = 0x01
	AcctStatusError   = 0x02
	AcctStatusFollow  = 0x21

	AuthenMethodNotSet = 0x00
	AuthenMethodNone   = 0x01
	AuthenMethodKRB5   = 0x02
	AuthenMethodLine   = 0x03
	AuthenMethodEnable = 0x04
	AuthenMethodLocal  = 0x05
	AuthenMethodTACACS = 0x06
	AuthenMethodGuest  = 0x08
	AuthenMethodRADIUS = 0x10
	AuthenMethodKRB4   = 0x11
	AuthenMethodRCMD   = 0x20

	PrivLvlMin = 0x00
	PrivLvlMax = 0x0f

	// DefaultCHAPMinChallenge is the recommended minimum CHAP challenge (RFC 8907 §5.4.2.3).
	DefaultCHAPMinChallenge = 8
	// MinCHAPChallenge is the RFC 8907 MUST floor (5 octets).
	MinCHAPChallenge = 5

	MSCHAPv1ChallengeLen = 8
	MSCHAPv2ChallengeLen = 16
	MSCHAPResponseLen    = 49
	CHAPResponseLen      = 16

	// DefaultMaxContinues bounds ASCII CONTINUE rounds before wrap.
	DefaultMaxContinues = 32

	ArgSepMandatory = '='
	ArgSepOptional  = '*'
)

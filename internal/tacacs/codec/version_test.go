package codec

import "testing"

func TestClassifyAuthenStartMatrix(t *testing.T) {
	t.Parallel()
	type row struct {
		name  string
		minor byte
		s     AuthenStart
		flow  Flow
		disp  Disposition
	}
	rows := []row{
		{"ascii minor0", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowASCIILogin, DispositionAccept},
		{"ascii minor1 fail", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowASCIILogin, DispositionFail},
		{"pap minor1", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypePAP, Service: AuthenServicePPP}, FlowPAPLogin, DispositionAccept},
		{"pap minor0 fail", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypePAP, Service: AuthenServicePPP}, FlowPAPLogin, DispositionFail},
		{"chap minor1", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeCHAP, Service: AuthenServicePPP}, FlowCHAPLogin, DispositionAccept},
		{"mschapv1 minor1", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeMSCHAP, Service: AuthenServicePPP}, FlowMSCHAPv1, DispositionAccept},
		{"mschapv2 minor1", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeMSCHAPV2, Service: AuthenServicePPP}, FlowMSCHAPv2, DispositionAccept},
		{"enable ascii ignore type", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceEnable}, FlowEnable, DispositionAccept},
		{"enable pap ignore type", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypePAP, Service: AuthenServiceEnable}, FlowEnable, DispositionAccept},
		{"enable unknown type ignore", 0, AuthenStart{Action: AuthenActionLogin, Type: 0x99, Service: AuthenServiceEnable}, FlowEnable, DispositionAccept},
		{"enable minor1 fail", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypePAP, Service: AuthenServiceEnable}, FlowEnable, DispositionFail},
		{"chpass ascii", 0, AuthenStart{Action: AuthenActionCHPASS, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowASCIIChpass, DispositionAccept},
		{"chpass minor1 fail", 1, AuthenStart{Action: AuthenActionCHPASS, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowASCIIChpass, DispositionFail},
		{"chpass enable fail", 0, AuthenStart{Action: AuthenActionCHPASS, Type: AuthenTypeASCII, Service: AuthenServiceEnable}, FlowNone, DispositionFail},
		{"sendauth error", 0, AuthenStart{Action: AuthenActionSendAuth, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowNone, DispositionError},
		{"sendpass error", 0, AuthenStart{Action: AuthenActionSendPass, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowNone, DispositionError},
		{"unknown action error", 0, AuthenStart{Action: 0x10, Type: AuthenTypeASCII, Service: AuthenServiceLogin}, FlowNone, DispositionError},
		{"unknown type error", 0, AuthenStart{Action: AuthenActionLogin, Type: 0x99, Service: AuthenServiceLogin}, FlowNone, DispositionError},
		{"arap type error", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeARAP, Service: AuthenServiceLogin}, FlowNone, DispositionError},
		{"ascii none service fail", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceNone}, FlowASCIILogin, DispositionFail},
		{"pap none service fail", 1, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypePAP, Service: AuthenServiceNone}, FlowPAPLogin, DispositionFail},
		{"unknown service fail", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: 0xaa}, FlowASCIILogin, DispositionFail},
		{"arap service fail", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceARAP}, FlowASCIILogin, DispositionFail},
		{"ascii ppp accept", 0, AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServicePPP}, FlowASCIILogin, DispositionAccept},
	}
	for _, r := range rows {
		flow, disp := ClassifyAuthenStart(r.minor, r.s)
		if flow != r.flow || disp != r.disp {
			t.Fatalf("%s: got flow=%d disp=%d want flow=%d disp=%d", r.name, flow, disp, r.flow, r.disp)
		}
	}
}

func TestKnownServices(t *testing.T) {
	t.Parallel()
	for _, s := range []byte{
		AuthenServiceNone, AuthenServiceLogin, AuthenServiceEnable, AuthenServicePPP,
		AuthenServicePT, AuthenServiceRCMD, AuthenServiceX25, AuthenServiceNASI, AuthenServiceFWProxy,
	} {
		if !KnownAuthenService(s) {
			t.Fatalf("service %#x", s)
		}
	}
	if KnownAuthenService(0x0a) || KnownAuthenService(AuthenServiceARAP) {
		t.Fatal("0x0a and ARAP 0x04 are unknown in RFC 8907")
	}
}

func TestDispositionAuthenStatus(t *testing.T) {
	t.Parallel()
	if DispositionFail.AuthenStatus() != AuthenStatusFail || DispositionError.AuthenStatus() != AuthenStatusError {
		t.Fatal("status map")
	}
}

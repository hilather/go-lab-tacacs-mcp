package domain

import "testing"

func TestAuthenTypeRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []AuthenType{AuthenTypeASCII, AuthenTypePAP, AuthenTypeCHAP, AuthenTypeARAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPV2}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseAuthenType(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if AuthenType(0x99).Valid() || AuthenType(0x99).String() != "" {
		t.Fatal("unknown type must not invent a name")
	}
	if _, err := ParseAuthenType("0x01"); err == nil {
		t.Fatal("numeric fallback is forbidden")
	}
	if _, err := ParseAuthenType(""); err == nil {
		t.Fatal("empty parse must fail")
	}
	if got, err := ParseAuthenType("MSCHAPV1"); err != nil || got != AuthenTypeMSCHAP {
		t.Fatalf("mschapv1 alias: %v %v", got, err)
	}
}

func TestAuthenMethodRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []AuthenMethod{
		AuthenMethodNotSet, AuthenMethodNone, AuthenMethodKRB5, AuthenMethodLine,
		AuthenMethodEnable, AuthenMethodLocal, AuthenMethodTACACS, AuthenMethodGuest,
		AuthenMethodRADIUS, AuthenMethodKRB4, AuthenMethodRCMD,
	}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseAuthenMethod(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if AuthenMethod(0x99).Valid() || AuthenMethod(0x99).String() != "" {
		t.Fatal("unknown method must not invent a name")
	}
	if _, err := ParseAuthenMethod("ascii"); err == nil {
		t.Fatal("type name must not parse as a method")
	}
	got, err := ParseAuthenMethod("tacacs+")
	if err != nil || got != AuthenMethodTACACS {
		t.Fatalf("tacacs+ alias: %v %v", got, err)
	}
}

func TestAuthenServiceRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []AuthenService{
		AuthenServiceNone, AuthenServiceLogin, AuthenServiceEnable, AuthenServicePPP,
		AuthenServiceARAP, AuthenServicePT, AuthenServiceRCMD, AuthenServiceX25,
		AuthenServiceNASI, AuthenServiceFWProxy,
	}
	for _, v := range vals {
		got, err := ParseAuthenService(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if AuthenService(0xff).String() != "" {
		t.Fatal("unknown service must not invent a name")
	}
	if _, err := ParseAuthenService("99"); err == nil {
		t.Fatal("numeric fallback is forbidden")
	}
}

func TestAuthenActionAndStatusRoundTrip(t *testing.T) {
	t.Parallel()
	actions := []AuthenAction{AuthenActionLogin, AuthenActionCHPASS, AuthenActionSendPass, AuthenActionSendAuth}
	for _, v := range actions {
		got, err := ParseAuthenAction(v.String())
		if err != nil || got != v {
			t.Fatalf("action %q", v)
		}
	}
	statuses := []AuthenStatus{
		AuthenStatusPass, AuthenStatusFail, AuthenStatusGetData, AuthenStatusGetUser,
		AuthenStatusGetPass, AuthenStatusRestart, AuthenStatusError, AuthenStatusFollow,
	}
	for _, v := range statuses {
		got, err := ParseAuthenStatus(v.String())
		if err != nil || got != v {
			t.Fatalf("status %q", v)
		}
	}
}

func TestAuthorDecisionNoYAMLPermitAlias(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"permit_add", "permit_replace", "deny"} {
		d, err := ParseAuthorDecision(s)
		if err != nil || !d.Valid() {
			t.Fatalf("%s: %v %v", s, d, err)
		}
	}
	if _, err := ParseAuthorDecision("permit"); err == nil {
		t.Fatal("YAML-only permit alias must not be accepted by domain parse")
	}
	if DecisionPermitAdd.WireStatus() != AuthorStatusPassAdd {
		t.Fatal("permit_add wire")
	}
	if DecisionPermitReplace.WireStatus() != AuthorStatusPassRepl {
		t.Fatal("permit_replace wire")
	}
	if DecisionDeny.WireStatus() != AuthorStatusFail {
		t.Fatal("deny wire")
	}
	if AuthorDecision("nope").WireStatus() != AuthorStatusError {
		t.Fatal("unknown decision maps to author ERROR")
	}
}

func TestRuleKindAndTransportAndMatchMode(t *testing.T) {
	t.Parallel()
	if k, err := ParseRuleKind("service"); err != nil || k != RuleKindService {
		t.Fatal(err)
	}
	if k, err := ParseRuleKind("command"); err != nil || k != RuleKindCommand {
		t.Fatal(err)
	}
	if _, err := ParseRuleKind("mixed"); err == nil {
		t.Fatal("mixed kind")
	}
	if tr, err := ParseTransport("legacy"); err != nil || tr != TransportLegacy {
		t.Fatal(err)
	}
	if tr, err := ParseTransport("tls"); err != nil || tr != TransportTLS {
		t.Fatal(err)
	}
	if m, err := ParseMatchMode("address_and_certificate"); err != nil || m != MatchAddressAndCertificate {
		t.Fatal(err)
	}
	if m, err := ParseMatchMode("certificate_only"); err != nil || m != MatchCertificateOnly {
		t.Fatal(err)
	}
}

func TestAcctFlagsValidCombinations(t *testing.T) {
	t.Parallel()
	valid := []AcctFlags{AcctFlagStart, AcctFlagStop, AcctFlagWatchdog, AcctFlagsWatchdogUpdate}
	for _, f := range valid {
		if !f.Valid() {
			t.Fatalf("%#x", f)
		}
		got, err := ParseAcctFlags(f.String())
		if err != nil || got != f {
			t.Fatalf("%q: %v %v", f.String(), got, err)
		}
	}
	invalid := []AcctFlags{0, AcctFlagStart | AcctFlagStop, AcctFlagWatchdog | AcctFlagStop, 0xff}
	for _, f := range invalid {
		if f.Valid() {
			t.Fatalf("%#x must be invalid", f)
		}
		if f.String() != "" {
			t.Fatalf("invalid flags must not invent a name: %#x -> %q", f, f.String())
		}
	}
}

func TestPrivilegeLevelBounds(t *testing.T) {
	t.Parallel()
	for _, v := range []int{0, 1, 15} {
		p, err := ParsePrivilegeLevel(v)
		if err != nil || int(p) != v {
			t.Fatalf("%d: %v %v", v, p, err)
		}
	}
	for _, v := range []int{-1, 16, 255} {
		if _, err := ParsePrivilegeLevel(v); err == nil {
			t.Fatalf("accepted %d", v)
		}
	}
}

func TestPacketFamily(t *testing.T) {
	t.Parallel()
	if !PacketAuthen.Valid() || PacketAuthen.String() != "authen" {
		t.Fatal(PacketAuthen)
	}
	if !PacketAuthor.Valid() || !PacketAcct.Valid() {
		t.Fatal("author/acct")
	}
	if PacketFamily(0).Valid() || PacketFamily(0).String() != "" {
		t.Fatal("unknown packet family")
	}
}

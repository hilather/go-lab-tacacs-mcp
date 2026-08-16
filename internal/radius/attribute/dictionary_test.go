package attribute

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestBuiltinMVPComplete(t *testing.T) {
	t.Parallel()
	d := Builtin()
	if d.Version() != DictionaryVersion || DictionaryVersion != "builtin-mvp-1" {
		t.Fatalf("version=%q", d.Version())
	}
	want := []struct {
		name string
		code uint8
		kind ValueKind
		card Cardinality
		sens Sensitivity
	}{
		{"User-Name", TypeUserName, KindText, CardinalitySingle, SensitivityRestricted},
		{"User-Password", TypeUserPassword, KindString, CardinalitySingle, SensitivitySecret},
		{"CHAP-Password", TypeCHAPPassword, KindString, CardinalitySingle, SensitivitySecret},
		{"NAS-IP-Address", TypeNASIPAddress, KindIPv4, CardinalitySingle, SensitivityRestricted},
		{"NAS-Port", TypeNASPort, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Service-Type", TypeServiceType, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Framed-Protocol", TypeFramedProtocol, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Framed-IP-Address", TypeFramedIPAddress, KindIPv4, CardinalitySingle, SensitivityPublic},
		{"Filter-Id", TypeFilterID, KindText, CardinalityMulti, SensitivityPublic},
		{"Framed-MTU", TypeFramedMTU, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Reply-Message", TypeReplyMessage, KindText, CardinalityMulti, SensitivityPublic},
		{"State", TypeState, KindString, CardinalitySingle, SensitivitySecret},
		{"Class", TypeClass, KindString, CardinalityMulti, SensitivityRestricted},
		{"Vendor-Specific", TypeVendorSpecific, KindVSA, CardinalityMulti, SensitivityRestricted},
		{"Session-Timeout", TypeSessionTimeout, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Idle-Timeout", TypeIdleTimeout, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Called-Station-Id", TypeCalledStationID, KindText, CardinalitySingle, SensitivityRestricted},
		{"Calling-Station-Id", TypeCallingStationID, KindText, CardinalitySingle, SensitivityRestricted},
		{"NAS-Identifier", TypeNASIdentifier, KindText, CardinalitySingle, SensitivityRestricted},
		{"Proxy-State", TypeProxyState, KindString, CardinalityMulti, SensitivityPublic},
		{"Acct-Status-Type", TypeAcctStatusType, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Delay-Time", TypeAcctDelayTime, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Input-Octets", TypeAcctInputOctets, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Output-Octets", TypeAcctOutputOctets, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Session-Id", TypeAcctSessionID, KindText, CardinalitySingle, SensitivityRestricted},
		{"Acct-Authentic", TypeAcctAuthentic, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Session-Time", TypeAcctSessionTime, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Input-Packets", TypeAcctInputPackets, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Output-Packets", TypeAcctOutputPackets, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Terminate-Cause", TypeAcctTerminateCause, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Input-Gigawords", TypeAcctInputGigawords, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Acct-Output-Gigawords", TypeAcctOutputGigawords, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Event-Timestamp", TypeEventTimestamp, KindTime, CardinalitySingle, SensitivityPublic},
		{"CHAP-Challenge", TypeCHAPChallenge, KindString, CardinalitySingle, SensitivityPublic},
		{"NAS-Port-Type", TypeNASPortType, KindInteger, CardinalitySingle, SensitivityPublic},
		{"Message-Authenticator", TypeMessageAuthenticator, KindString, CardinalitySingle, SensitivitySecret},
		{"Acct-Interim-Interval", TypeAcctInterimInterval, KindInteger, CardinalitySingle, SensitivityPublic},
		{"NAS-IPv6-Address", TypeNASIPv6Address, KindIPv6, CardinalitySingle, SensitivityRestricted},
		{"MS-CHAP-Response", VendorTypeMSCHAPResponse, KindString, CardinalitySingle, SensitivitySecret},
		{"MS-CHAP-Error", VendorTypeMSCHAPError, KindText, CardinalitySingle, SensitivitySecret},
		{"MS-CHAP-Challenge", VendorTypeMSCHAPChallenge, KindString, CardinalitySingle, SensitivitySecret},
		{"MS-CHAP2-Response", VendorTypeMSCHAP2Response, KindString, CardinalitySingle, SensitivitySecret},
		{"MS-CHAP2-Success", VendorTypeMSCHAP2Success, KindString, CardinalitySingle, SensitivitySecret},
		{NameCiscoAVPair, TypeCiscoAVPair, KindText, CardinalityMulti, SensitivityRestricted},
		{"Error-Cause", TypeErrorCause, KindInteger, CardinalitySingle, SensitivityPublic},
	}
	all := d.All()
	if len(all) != len(want) {
		t.Fatalf("len=%d want %d", len(all), len(want))
	}
	seen := make(map[string]int, len(want))
	for i, w := range want {
		def, ok := d.LookupName(w.name)
		if !ok {
			t.Fatalf("missing name %s", w.name)
		}
		if w.name == NameCiscoAVPair {
			byKey, ok := d.LookupKey(CiscoAVPairKey())
			if !ok || byKey.Name != w.name || byKey.Vendor != VendorCisco {
				t.Fatalf("lookup cisco key: %+v ok=%v", byKey, ok)
			}
			if _, ok := d.LookupIETF(w.code); !ok {
				t.Fatal("IETF type 1 must remain User-Name")
			}
		} else if def.Vendor == 0 {
			byCode, ok := d.LookupIETF(w.code)
			if !ok || byCode.Name != w.name {
				t.Fatalf("lookup code %d: %+v ok=%v", w.code, byCode, ok)
			}
		} else if def.Vendor != VendorMicrosoft {
			t.Fatalf("%s vendor=%d", w.name, def.Vendor)
		}
		if def.Kind != w.kind || def.Cardinality != w.card || def.Sensitivity != w.sens || def.Code != w.code {
			t.Fatalf("%s: kind=%s card=%s sens=%s code=%d", w.name, def.Kind, def.Cardinality, def.Sensitivity, def.Code)
		}
		if all[i].Name != w.name {
			t.Fatalf("order[%d]=%s want %s", i, all[i].Name, w.name)
		}
		seen[w.name]++
	}
	if _, ok := d.LookupName("user-name"); ok {
		t.Fatal("lookup is case-sensitive")
	}
	if len(seen) != len(want) {
		t.Fatal("duplicate names in expected table")
	}
}

func TestNamedMicrosoftVSAs(t *testing.T) {
	t.Parallel()
	d := Builtin()
	for _, name := range []string{"MS-CHAP-Challenge", "MS-CHAP-Response", "MS-CHAP2-Response", "MS-CHAP2-Success", "MS-CHAP-Error"} {
		def, ok := d.LookupName(name)
		if !ok || def.Vendor != VendorMicrosoft || def.Sensitivity != SensitivitySecret {
			t.Fatalf("%s: %+v ok=%v", name, def, ok)
		}
		if _, ok := d.LookupKey(Key{Vendor: VendorMicrosoft, Code: uint32(def.Code), Space: SpaceVSA}); !ok {
			t.Fatalf("lookup key %s", name)
		}
	}
	if _, ok := d.LookupIETF(VendorTypeMSCHAPResponse); !ok {
		t.Fatal("IETF type 1 remains User-Name")
	}
	user, _ := d.LookupIETF(1)
	if user.Name != "User-Name" {
		t.Fatalf("IETF 1=%s", user.Name)
	}
}

func TestNamedCiscoAVPair(t *testing.T) {
	t.Parallel()
	d := Builtin()
	def, ok := d.LookupName(NameCiscoAVPair)
	if !ok {
		t.Fatal("named Cisco-AVPair must be in the builtin dictionary")
	}
	if def.Vendor != VendorCisco || def.Code != TypeCiscoAVPair || def.Kind != KindText ||
		def.Cardinality != CardinalityMulti || def.Sensitivity != SensitivityRestricted {
		t.Fatalf("cisco def=%+v", def)
	}
	if !def.AllowedIn(PacketAccessRequest) || !def.AllowedIn(PacketAccessAccept) ||
		!def.AllowedIn(PacketAccessReject) || !def.AllowedIn(PacketAccessChallenge) ||
		!def.AllowedIn(PacketAccountingRequest) || def.AllowedIn(PacketAccountingResponse) {
		t.Fatalf("cisco packet roles=%v", def.AllowedPackets())
	}
	if _, ok := d.LookupKey(CiscoAVPairKey()); !ok {
		t.Fatal("vendor 9 code 1 must be named")
	}
	if _, ok := d.LookupKey(Key{Vendor: VendorCisco, Code: 1, Space: SpaceIETF}); ok {
		t.Fatal("vendor 9 IETF space must not exist")
	}
	if user, ok := d.LookupIETF(TypeUserName); !ok || user.Name != "User-Name" {
		t.Fatal("IETF User-Name must stay type 1")
	}
}

func TestUnknownPreservedAndSummarized(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-UNK-VALUE-zz"
	raw := Raw{Type: 200, Value: []byte(canary)}
	set := RawSet{raw, {Type: TypeUserName, Value: []byte("lab-admin")}}
	wire, err := Encode(set)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 2 || got[0].Type != 200 || string(got[0].Value) != canary {
		t.Fatalf("unknown not preserved: %s", describeSet(got))
	}
	if err := Builtin().CheckSet(got, PacketAccessRequest); err != nil {
		t.Fatalf("unknown request: %v", err)
	}
	if err := Builtin().CheckSet(got, PacketAccessAccept); !errors.Is(err, ErrIllegalRole) {
		t.Fatalf("unknown response: %v", err)
	}
	sum := Builtin().Summarize(raw)
	if sum.Known || sum.Name != "" || sum.Sensitivity != SensitivityUnknown || sum.Type != 200 || sum.Length != len(canary) {
		t.Fatalf("summary=%+v", sum)
	}
	if strings.Contains(sum.String(), canary) {
		t.Fatal("summary leaked value")
	}
}

func TestCardinalitySingleVsMulti(t *testing.T) {
	t.Parallel()
	ma := maAttr()
	user := Raw{Type: TypeUserName, Value: []byte("a")}
	if err := Builtin().CheckSet(RawSet{user, user}, PacketAccessRequest); !errors.Is(err, ErrCardinality) {
		t.Fatalf("dup user: %v", err)
	}
	if err := Builtin().CheckSet(RawSet{ma, ma}, PacketAccessRequest); !errors.Is(err, ErrCardinality) {
		t.Fatalf("dup ma: %v", err)
	}
	pw := Raw{Type: TypeUserPassword, Value: make([]byte, 16)}
	if err := Builtin().CheckSet(RawSet{pw, pw}, PacketAccessRequest); !errors.Is(err, ErrCardinality) {
		t.Fatalf("dup password: %v", err)
	}
	chap := Raw{Type: TypeCHAPPassword, Value: make([]byte, 17)}
	if err := Builtin().CheckSet(RawSet{chap, chap}, PacketAccessRequest); !errors.Is(err, ErrCardinality) {
		t.Fatalf("dup chap: %v", err)
	}
	ps := RawSet{
		{Type: TypeProxyState, Value: []byte("one")},
		{Type: TypeProxyState, Value: []byte("two")},
	}
	if err := Builtin().CheckSet(ps, PacketAccessRequest); err != nil {
		t.Fatalf("multi proxy-state: %v", err)
	}
}

func TestMessageAuthenticatorRoles(t *testing.T) {
	t.Parallel()
	d := Builtin()
	ma, ok := d.LookupName("Message-Authenticator")
	if !ok {
		t.Fatal("missing MA")
	}
	if !ma.AllowedIn(PacketAccountingRequest) || ma.RequiredIn(PacketAccountingRequest) || ma.MustBeFirst(PacketAccountingRequest) {
		t.Fatal("Accounting-Request: MA allowed, not required, not first")
	}
	if !ma.AllowedIn(PacketAccessRequest) || ma.RequiredIn(PacketAccessRequest) {
		t.Fatal("Access-Request: MA allowed, not required")
	}
	for _, pkt := range []uint8{PacketAccessAccept, PacketAccessReject, PacketAccessChallenge, PacketAccountingResponse} {
		if !ma.AllowedIn(pkt) || !ma.RequiredIn(pkt) || !ma.MustBeFirst(pkt) {
			t.Fatalf("response %s: MA must be required first", packetName(pkt))
		}
		first, ok := d.RequiredFirst(pkt)
		if !ok || first.Code != TypeMessageAuthenticator {
			t.Fatalf("RequiredFirst(%s)=%v ok=%v", packetName(pkt), first, ok)
		}
	}
}

func TestCheckSetMessageAuthenticatorMatrix(t *testing.T) {
	t.Parallel()
	d := Builtin()
	ma := maAttr()
	acct := Raw{Type: TypeAcctStatusType, Value: []byte{0, 0, 0, 1}}
	reply := Raw{Type: TypeReplyMessage, Value: []byte("no")}
	proxy := Raw{Type: TypeProxyState, Value: []byte("p")}

	if err := d.CheckSet(RawSet{acct, ma}, PacketAccountingRequest); err != nil {
		t.Fatalf("acct-req with MA: %v", err)
	}
	if err := d.CheckSet(RawSet{acct}, PacketAccountingRequest); err != nil {
		t.Fatalf("acct-req without MA: %v", err)
	}

	if err := d.CheckSet(RawSet{ma, reply}, PacketAccessAccept); err != nil {
		t.Fatalf("accept MA first: %v", err)
	}
	if err := d.CheckSet(RawSet{reply}, PacketAccessAccept); !errors.Is(err, ErrMissingRequired) {
		t.Fatalf("accept missing MA: %v", err)
	}
	if err := d.CheckSet(RawSet{reply, ma}, PacketAccessAccept); !errors.Is(err, ErrNotFirst) {
		t.Fatalf("accept MA not first: %v", err)
	}

	if err := d.CheckSet(RawSet{ma, reply}, PacketAccessReject); err != nil {
		t.Fatalf("reject MA first: %v", err)
	}
	if err := d.CheckSet(RawSet{reply, ma}, PacketAccessReject); !errors.Is(err, ErrNotFirst) {
		t.Fatalf("reject MA not first: %v", err)
	}

	if err := d.CheckSet(RawSet{ma, proxy}, PacketAccountingResponse); err != nil {
		t.Fatalf("acct-resp MA first: %v", err)
	}
	if err := d.CheckSet(RawSet{proxy}, PacketAccountingResponse); !errors.Is(err, ErrMissingRequired) {
		t.Fatalf("acct-resp missing MA: %v", err)
	}
	if err := d.CheckSet(RawSet{proxy, ma}, PacketAccountingResponse); !errors.Is(err, ErrNotFirst) {
		t.Fatalf("acct-resp MA not first: %v", err)
	}

	if err := d.CheckSet(RawSet{ma, reply}, PacketAccessChallenge); err != nil {
		t.Fatalf("challenge MA first: %v", err)
	}
}

func TestCheckSetIllegalRoles(t *testing.T) {
	t.Parallel()
	d := Builtin()
	ma := maAttr()
	cases := []struct {
		name   string
		set    RawSet
		packet uint8
	}{
		{"password-on-accept", RawSet{ma, {Type: TypeUserPassword, Value: make([]byte, 16)}}, PacketAccessAccept},
		{"filter-on-request", RawSet{{Type: TypeFilterID, Value: []byte("acl")}}, PacketAccessRequest},
		{"acct-status-on-access", RawSet{{Type: TypeAcctStatusType, Value: []byte{0, 0, 0, 1}}}, PacketAccessRequest},
		{"session-timeout-on-acct", RawSet{{Type: TypeAcctStatusType, Value: []byte{0, 0, 0, 1}}, {Type: TypeSessionTimeout, Value: []byte{0, 0, 0, 1}}}, PacketAccountingRequest},
		{"reply-on-acct-req", RawSet{{Type: TypeAcctStatusType, Value: []byte{0, 0, 0, 1}}, {Type: TypeReplyMessage, Value: []byte("x")}}, PacketAccountingRequest},
		{"filter-on-reject", RawSet{ma, {Type: TypeFilterID, Value: []byte("acl")}}, PacketAccessReject},
		{"vsa-on-acct-resp", RawSet{ma, {Type: TypeVendorSpecific, Value: []byte{0, 0, 0, 9}}}, PacketAccountingResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := d.CheckSet(tc.set, tc.packet); !errors.Is(err, ErrIllegalRole) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCheckSetRequiredAcctStatus(t *testing.T) {
	t.Parallel()
	if err := Builtin().CheckSet(RawSet{{Type: TypeUserName, Value: []byte("a")}}, PacketAccountingRequest); !errors.Is(err, ErrMissingRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckSetValueLengths(t *testing.T) {
	t.Parallel()
	d := Builtin()
	if err := d.CheckSet(RawSet{{Type: TypeCHAPPassword, Value: make([]byte, 16)}}, PacketAccessRequest); !errors.Is(err, ErrValueLength) {
		t.Fatalf("chap: %v", err)
	}
	if err := d.CheckSet(RawSet{{Type: TypeMessageAuthenticator, Value: make([]byte, 15)}}, PacketAccessRequest); !errors.Is(err, ErrValueLength) {
		t.Fatalf("ma: %v", err)
	}
	if err := d.CheckSet(RawSet{{Type: TypeNASPort, Value: []byte{1, 2}}}, PacketAccessRequest); !errors.Is(err, ErrValueLength) {
		t.Fatalf("int: %v", err)
	}
}

func TestCheckSetUnknownPacket(t *testing.T) {
	t.Parallel()
	if err := Builtin().CheckSet(nil, 99); !errors.Is(err, ErrUnknownPacket) {
		t.Fatalf("err=%v", err)
	}
}

func TestSensitivityMetadata(t *testing.T) {
	t.Parallel()
	if !Sensitive(TypeUserPassword) || !Sensitive(TypeCHAPPassword) || !Sensitive(TypeMessageAuthenticator) || !Sensitive(TypeState) {
		t.Fatal("secret types")
	}
	if Sensitive(TypeUserName) || Sensitive(TypeVendorSpecific) || Sensitive(200) {
		t.Fatal("non-secret types")
	}
	if !Restricted(TypeUserName) || !Restricted(TypeCallingStationID) || !Restricted(TypeAcctSessionID) || !Restricted(TypeVendorSpecific) {
		t.Fatal("restricted types")
	}
	if Restricted(TypeReplyMessage) || Restricted(TypeUserPassword) {
		t.Fatal("reply/password classification")
	}
	if Builtin().SensitivityOf(200) != SensitivityUnknown {
		t.Fatal("unknown sensitivity")
	}
}

func TestSummarizeAndErrorsNeverPrintValues(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-DICT-SECRET-yy"
	raw := Raw{Type: TypeUserPassword, Value: []byte(canary)}
	sum := Builtin().Summarize(raw)
	err := Builtin().CheckSet(RawSet{raw, raw}, PacketAccessRequest)
	def, _ := Builtin().LookupName("User-Password")
	blob := fmt.Sprintf("%v %s %#v %v %s %v %s %#v", sum, sum, sum, err, err, def, def, def)
	if strings.Contains(blob, canary) {
		t.Fatalf("value leaked: %s", blob)
	}
	if !strings.Contains(sum.String(), "sensitivity=secret") {
		t.Fatalf("summary=%s", sum)
	}
}

func TestSummarizeVSAHasVendorNoPayload(t *testing.T) {
	t.Parallel()
	const canary = "CANARY-VSA-PAYLOAD-qq"
	raw, err := (VSA{Vendor: 9, Payload: []byte(canary)}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	sum := Builtin().Summarize(raw)
	if !sum.Known || sum.Vendor != 9 || sum.Name != "Vendor-Specific" || sum.Sensitivity != SensitivityRestricted {
		t.Fatalf("sum=%+v", sum)
	}
	if strings.Contains(sum.String(), canary) {
		t.Fatal("vsa payload leaked")
	}
}

func TestConcurrentDictionaryLookups(t *testing.T) {
	t.Parallel()
	d := Builtin()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if _, ok := d.LookupName("User-Name"); !ok {
					t.Error("lookup")
					return
				}
				_ = d.AllowedIn(TypeProxyState, PacketAccessAccept)
				_ = d.CheckSet(RawSet{maAttr(), {Type: TypeReplyMessage, Value: []byte("x")}}, PacketAccessAccept)
				_ = d.All()
			}
		}()
	}
	wg.Wait()
}

func maAttr() Raw {
	return Raw{Type: TypeMessageAuthenticator, Value: make([]byte, 16)}
}

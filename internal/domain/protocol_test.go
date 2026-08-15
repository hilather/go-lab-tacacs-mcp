package domain

import (
	"strings"
	"testing"
)

func TestProtocolRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []Protocol{ProtocolTACACS, ProtocolRADIUS, ProtocolHTTP}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseProtocol(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
		upper, err := ParseProtocol(strings.ToUpper(v.String()))
		if err != nil || upper != v {
			t.Fatalf("Parse(%q)=%v err=%v", strings.ToUpper(v.String()), upper, err)
		}
	}
	if Protocol("").Valid() {
		t.Fatal("empty protocol must be invalid")
	}
	if Protocol("udp").Valid() {
		t.Fatal("udp is not a protocol")
	}
	if _, err := ParseProtocol(""); err == nil {
		t.Fatal("empty parse must fail")
	}
	if _, err := ParseProtocol("tacacs+"); err == nil {
		t.Fatal("tacacs+ is AuthenMethod, not Protocol")
	}
}

func TestListenerRoleRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []ListenerRole{
		RoleAuthentication, RoleAuthorization, RoleAccounting,
		RoleAccess, RoleAdmin, RoleAAA, RoleDynamicAuthorization,
	}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseListenerRole(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if RoleAAA.String() != "aaa" {
		t.Fatalf("TACACS sockets use RoleAAA, got %q", RoleAAA)
	}
	if _, err := ParseListenerRole("mixed"); err == nil {
		t.Fatal("mixed role")
	}
	if _, err := ParseListenerRole(""); err == nil {
		t.Fatal("empty role")
	}
	if ListenerRole("authen").Valid() {
		t.Fatal("TACACS packet family name is not a listener role")
	}
}

func TestCarrierRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []Carrier{
		CarrierTACACSLegacyTCP, CarrierTACACSTLS, CarrierRADIUSUDP,
		CarrierHTTPTCP, CarrierRADIUSTLS,
	}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseCarrier(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if CarrierRADIUSUDP.String() != "radius_udp" {
		t.Fatalf("got %q", CarrierRADIUSUDP)
	}
	if _, err := ParseCarrier("legacy"); err == nil {
		t.Fatal("Transport token must not parse as Carrier")
	}
	if _, err := ParseCarrier("udp"); err == nil {
		t.Fatal("bare udp is a status string, not a Carrier")
	}
	if _, err := ParseCarrier(""); err == nil {
		t.Fatal("empty carrier")
	}
}

func TestTransportRemainsTACACSLegacyOrTLS(t *testing.T) {
	t.Parallel()
	if !TransportLegacy.Valid() || TransportLegacy.String() != "legacy" {
		t.Fatal(TransportLegacy)
	}
	if !TransportTLS.Valid() || TransportTLS.String() != "tls" {
		t.Fatal(TransportTLS)
	}
	for _, s := range []string{"udp", "radius_udp", "http", "tcp", "radius", "tacacs_legacy_tcp", ""} {
		if Transport(s).Valid() {
			t.Fatalf("Transport(%q) must not be valid", s)
		}
		if _, err := ParseTransport(s); err == nil {
			t.Fatalf("ParseTransport(%q) must fail", s)
		}
	}
	if tr, err := ParseTransport("legacy"); err != nil || tr != TransportLegacy {
		t.Fatal(err)
	}
	if tr, err := ParseTransport("tls"); err != nil || tr != TransportTLS {
		t.Fatal(err)
	}
}

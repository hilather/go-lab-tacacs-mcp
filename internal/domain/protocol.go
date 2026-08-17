package domain

import "strings"

// Protocol names the AAA or admin protocol a listener or request belongs to.
// This is distinct from Transport, which remains TACACS legacy/tls only.
type Protocol string

const (
	ProtocolTACACS Protocol = "tacacs"
	ProtocolRADIUS Protocol = "radius"
	ProtocolHTTP   Protocol = "http" // admin listener only
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolTACACS, ProtocolRADIUS, ProtocolHTTP:
		return true
	default:
		return false
	}
}

func (p Protocol) String() string { return string(p) }

// ParseProtocol accepts tacacs, radius, or http only.
func ParseProtocol(s string) (Protocol, error) {
	p := Protocol(strings.ToLower(s))
	if !p.Valid() {
		return "", NewError(CodeInvalidArgument, "protocol must be tacacs, radius, or http")
	}
	return p, nil
}

// ListenerRole is the function of a bound socket or request path.
type ListenerRole string

const (
	RoleAuthentication       ListenerRole = "authentication"
	RoleAuthorization        ListenerRole = "authorization"
	RoleAccounting           ListenerRole = "accounting"
	RoleAccess               ListenerRole = "access"
	RoleAdmin                ListenerRole = "admin"
	RoleAAA                  ListenerRole = "aaa"                   // TACACS combined auth+author+acct socket
	RoleDynamicAuthorization ListenerRole = "dynamic_authorization" // reserved, not MVP
)

func (r ListenerRole) Valid() bool {
	switch r {
	case RoleAuthentication, RoleAuthorization, RoleAccounting, RoleAccess,
		RoleAdmin, RoleAAA, RoleDynamicAuthorization:
		return true
	default:
		return false
	}
}

func (r ListenerRole) String() string { return string(r) }

// ParseListenerRole accepts the closed listener-role set only.
func ParseListenerRole(s string) (ListenerRole, error) {
	r := ListenerRole(strings.ToLower(s))
	if !r.Valid() {
		return "", NewError(CodeInvalidArgument, "listener role must be authentication, authorization, accounting, access, admin, aaa, or dynamic_authorization")
	}
	return r, nil
}

// Carrier is the wire binding of a listener. It is not a Transport value.
type Carrier string

const (
	CarrierTACACSLegacyTCP Carrier = "tacacs_legacy_tcp"
	CarrierTACACSTLS       Carrier = "tacacs_tls"
	CarrierRADIUSUDP       Carrier = "radius_udp"
	CarrierHTTPTCP         Carrier = "http_tcp"
	CarrierRADIUSTLS       Carrier = "radius_tls"
)

func (c Carrier) Valid() bool {
	switch c {
	case CarrierTACACSLegacyTCP, CarrierTACACSTLS, CarrierRADIUSUDP, CarrierHTTPTCP, CarrierRADIUSTLS:
		return true
	default:
		return false
	}
}

func (c Carrier) String() string { return string(c) }

// ParseCarrier accepts the closed carrier set only.
func ParseCarrier(s string) (Carrier, error) {
	c := Carrier(strings.ToLower(s))
	if !c.Valid() {
		return "", NewError(CodeInvalidArgument, "carrier must be tacacs_legacy_tcp, tacacs_tls, radius_udp, http_tcp, or radius_tls")
	}
	return c, nil
}

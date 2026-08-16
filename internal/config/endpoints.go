package config

import (
	"reflect"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// SynthesizeTACACSEndpoints builds endpoints from flatten TACACS fields.
// Overlay apply uses this when a RADIUS endpoint is added to a flatten-only client.
func SynthesizeTACACSEndpoints(c Client) []ClientEndpoint {
	return synthesizeTACACSEndpoints(c)
}

// ApplyTACACSProjection rebuilds flatten TACACS fields from endpoints.
func ApplyTACACSProjection(c *Client) {
	if c == nil {
		return
	}
	applyTACACSProjection(c)
}

// TACACSProjectionMatches reports whether flatten TACACS fields match endpoints.
func TACACSProjectionMatches(c Client) bool {
	if len(c.Endpoints) == 0 {
		return true
	}
	return projectionMatchesClient(c, projectTACACS(c.Endpoints))
}

// synthesizeTACACSEndpoints builds endpoints from flatten TACACS fields.
// v1 and v2 documents without endpoints[] use this so Endpoints is canonical.
func synthesizeTACACSEndpoints(c Client) []ClientEndpoint {
	if len(c.Match.Transports) == 0 {
		return nil
	}
	out := make([]ClientEndpoint, 0, len(c.Match.Transports))
	for _, tr := range c.Match.Transports {
		ep := ClientEndpoint{
			Protocol: domain.ProtocolTACACS,
			Roles: []domain.ListenerRole{
				domain.RoleAuthentication,
				domain.RoleAuthorization,
				domain.RoleAccounting,
			},
			TACACS: &TACACSEndpoint{
				AllowedMethods:  copyAuthMethods(c.Authentication.AllowedMethods),
				DefaultService:  c.Authentication.DefaultService,
				DefaultGroupIDs: copyStrings(c.Authorization.DefaultGroupIDs),
				Accounting:      c.Accounting,
			},
		}
		switch tr {
		case domain.TransportLegacy:
			ep.ID = "tacacs-legacy"
			ep.Transport = EndpointTransportTCP
			ep.TACACS.SharedSecret = c.Legacy.SharedSecret
			ep.TACACS.SharedSecretLifecycle = cloneSecretLifecycle(c.Legacy.SharedSecretLifecycle)
		case domain.TransportTLS:
			ep.ID = "tacacs-tls"
			ep.Transport = EndpointTransportTLS
		default:
			continue
		}
		out = append(out, ep)
	}
	return out
}

func cloneSecretLifecycle(m SecretLifecycleMeta) SecretLifecycleMeta {
	return SecretLifecycleMeta{
		LastRotatedAt:    cloneTime(m.LastRotatedAt),
		RotationInterval: m.RotationInterval,
	}
}

func finalizeMissingEndpoints(clients []Client) {
	for i := range clients {
		if len(clients[i].Endpoints) == 0 {
			clients[i].Endpoints = synthesizeTACACSEndpoints(clients[i])
		}
	}
}

type tacacsProjection struct {
	Transports     []domain.Transport
	Legacy         ClientLegacy
	Authentication ClientAuth
	Authorization  ClientAuthz
	Accounting     ClientAcct
	Have           bool
}

func projectTACACS(eps []ClientEndpoint) tacacsProjection {
	var p tacacsProjection
	for _, ep := range eps {
		if ep.Protocol != domain.ProtocolTACACS || ep.TACACS == nil {
			continue
		}
		tr, ok := tacacsTransportFromEndpoint(ep.Transport)
		if !ok {
			continue
		}
		if !hasTransport(p.Transports, tr) {
			p.Transports = append(p.Transports, tr)
		}
		if tr == domain.TransportLegacy {
			p.Legacy = ClientLegacy{
				SharedSecret:          ep.TACACS.SharedSecret,
				SharedSecretLifecycle: cloneSecretLifecycle(ep.TACACS.SharedSecretLifecycle),
			}
		}
		if !p.Have {
			p.Authentication = ClientAuth{
				AllowedMethods: copyAuthMethods(ep.TACACS.AllowedMethods),
				DefaultService: ep.TACACS.DefaultService,
			}
			p.Authorization = ClientAuthz{DefaultGroupIDs: copyStrings(ep.TACACS.DefaultGroupIDs)}
			p.Accounting = ep.TACACS.Accounting
			p.Have = true
		}
	}
	return p
}

func applyTACACSProjection(c *Client) {
	p := projectTACACS(c.Endpoints)
	c.Match.Transports = p.Transports
	if p.Have {
		c.Legacy = p.Legacy
		c.Authentication = p.Authentication
		c.Authorization = p.Authorization
		c.Accounting = p.Accounting
	}
}

func projectionMatchesClient(c Client, p tacacsProjection) bool {
	if !sameTransports(c.Match.Transports, p.Transports) {
		return false
	}
	if !p.Have {
		return !c.Legacy.SharedSecret.Set() &&
			len(c.Authentication.AllowedMethods) == 0 &&
			(c.Authentication.DefaultService == domain.AuthenServiceNone || c.Authentication.DefaultService == 0) &&
			len(c.Authorization.DefaultGroupIDs) == 0
	}
	if !secretRefEqual(c.Legacy.SharedSecret, p.Legacy.SharedSecret) {
		return false
	}
	if !secretLifecycleEqual(c.Legacy.SharedSecretLifecycle, p.Legacy.SharedSecretLifecycle) {
		return false
	}
	if !reflect.DeepEqual(c.Authentication.AllowedMethods, p.Authentication.AllowedMethods) {
		return false
	}
	if c.Authentication.DefaultService != p.Authentication.DefaultService {
		return false
	}
	if !reflect.DeepEqual(c.Authorization.DefaultGroupIDs, p.Authorization.DefaultGroupIDs) {
		return false
	}
	return c.Accounting == p.Accounting
}

func sameTransports(a, b []domain.Transport) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func secretRefEqual(a, b SecretRef) bool {
	if !a.Set() && !b.Set() {
		return true
	}
	return a.Purpose == b.Purpose &&
		a.File == b.File &&
		a.Environment == b.Environment &&
		a.PreserveTrailingNewline == b.PreserveTrailingNewline &&
		a.MemoryID == b.MemoryID
}

func secretLifecycleEqual(a, b SecretLifecycleMeta) bool {
	if a.RotationInterval != b.RotationInterval {
		return false
	}
	if a.LastRotatedAt == nil && b.LastRotatedAt == nil {
		return true
	}
	if a.LastRotatedAt == nil || b.LastRotatedAt == nil {
		return false
	}
	return a.LastRotatedAt.Equal(*b.LastRotatedAt)
}

func checkClientProjection(c Client, path string) error {
	if len(c.Endpoints) == 0 {
		return nil
	}
	if !projectionMatchesClient(c, projectTACACS(c.Endpoints)) {
		return domain.NewError(domain.CodeClientEndpointProjectionMismatch, "client TACACS fields do not match endpoints").WithPath(path)
	}
	return nil
}

func flattenProtocolSpecified(raw rawClient) bool {
	if len(raw.Match.Transports) > 0 {
		return true
	}
	if raw.Legacy.SharedSecret != nil {
		return true
	}
	if len(raw.Authentication.AllowedMethods) > 0 || raw.Authentication.DefaultService != "" {
		return true
	}
	if len(raw.Authorization.DefaultGroupIDs) > 0 {
		return true
	}
	return raw.Accounting.Enabled != nil ||
		raw.Accounting.AcceptStart != nil ||
		raw.Accounting.AcceptStop != nil ||
		raw.Accounting.AcceptWatchdog != nil
}

func tacacsTransportFromEndpoint(transport string) (domain.Transport, bool) {
	switch transport {
	case EndpointTransportTCP:
		return domain.TransportLegacy, true
	case EndpointTransportTLS:
		return domain.TransportTLS, true
	default:
		return "", false
	}
}

func endpointHasRole(ep ClientEndpoint, role domain.ListenerRole) bool {
	for _, r := range ep.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func hasTACACSTLSEndpoint(c Client) bool {
	for _, ep := range c.Endpoints {
		if ep.Protocol == domain.ProtocolTACACS && ep.Transport == EndpointTransportTLS {
			return true
		}
	}
	// Flatten-only construction (no endpoints yet): TLS transport is the TLS endpoint.
	return hasTransport(c.Match.Transports, domain.TransportTLS)
}

func radiusEndpoint(c Client) *ClientEndpoint {
	for i := range c.Endpoints {
		if c.Endpoints[i].Protocol == domain.ProtocolRADIUS && c.Endpoints[i].RADIUS != nil {
			return &c.Endpoints[i]
		}
	}
	return nil
}

func hasRADIUSEndpoint(c Client) bool {
	return radiusEndpoint(c) != nil
}

func normalizeEndpoints(raw []rawClientEndpoint, path string, allowEnv bool, access RADIUSListener, flatten Client) ([]ClientEndpoint, error) {
	out := make([]ClientEndpoint, 0, len(raw))
	seen := map[string]struct{}{}
	var radiusCount, tacacsTCP, tacacsTLS int
	for i, r := range raw {
		epath := indexPath(path+".endpoints", i)
		ep, err := normalizeEndpoint(r, epath, allowEnv, access, flatten)
		if err != nil {
			return nil, err
		}
		if ep.ID == "" {
			return nil, yamlErrorAt(epath+".id", "id is required")
		}
		if _, ok := seen[ep.ID]; ok {
			return nil, yamlErrorAt(epath+".id", "duplicate endpoint id")
		}
		seen[ep.ID] = struct{}{}
		switch ep.Protocol {
		case domain.ProtocolRADIUS:
			radiusCount++
			if radiusCount > 1 {
				return nil, yamlErrorAt(epath, "a client may have at most one RADIUS UDP endpoint")
			}
		case domain.ProtocolTACACS:
			switch ep.Transport {
			case EndpointTransportTCP:
				tacacsTCP++
				if tacacsTCP > 1 {
					return nil, yamlErrorAt(epath, "a client may have at most one TACACS tcp endpoint")
				}
			case EndpointTransportTLS:
				tacacsTLS++
				if tacacsTLS > 1 {
					return nil, yamlErrorAt(epath, "a client may have at most one TACACS tls endpoint")
				}
			}
		}
		out = append(out, ep)
	}
	if err := tacacsEndpointsConsistent(out, path+".endpoints"); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeEndpoint(raw rawClientEndpoint, path string, allowEnv bool, access RADIUSListener, flatten Client) (ClientEndpoint, error) {
	proto, err := domain.ParseProtocol(raw.Protocol)
	if err != nil || proto == domain.ProtocolHTTP {
		return ClientEndpoint{}, yamlErrorAt(path+".protocol", "protocol must be tacacs or radius")
	}
	transport := strings.ToLower(strings.TrimSpace(raw.Transport))
	if err := validateEndpointPair(proto, transport, path); err != nil {
		return ClientEndpoint{}, err
	}
	roles, err := normalizeEndpointRoles(raw.Roles, proto, path+".roles")
	if err != nil {
		return ClientEndpoint{}, err
	}
	if raw.TACACS != nil && raw.RADIUS != nil {
		return ClientEndpoint{}, yamlErrorAt(path, "endpoint must set exactly one of tacacs or radius")
	}
	ep := ClientEndpoint{
		ID:        raw.ID,
		Protocol:  proto,
		Transport: transport,
		Roles:     roles,
	}
	switch proto {
	case domain.ProtocolTACACS:
		if raw.RADIUS != nil {
			return ClientEndpoint{}, yamlErrorAt(path+".radius", "radius block is not valid on a tacacs endpoint")
		}
		tac, err := normalizeTACACSEndpoint(raw.TACACS, path+".tacacs", allowEnv, flatten)
		if err != nil {
			return ClientEndpoint{}, err
		}
		ep.TACACS = tac
	case domain.ProtocolRADIUS:
		if raw.TACACS != nil {
			return ClientEndpoint{}, yamlErrorAt(path+".tacacs", "tacacs block is not valid on a radius endpoint")
		}
		rad, err := normalizeRADIUSEndpoint(raw.RADIUS, path+".radius", allowEnv, access, roles)
		if err != nil {
			return ClientEndpoint{}, err
		}
		ep.RADIUS = rad
	}
	return ep, nil
}

func validateEndpointPair(proto domain.Protocol, transport, path string) error {
	switch proto {
	case domain.ProtocolTACACS:
		switch transport {
		case EndpointTransportTCP, EndpointTransportTLS:
			return nil
		case "":
			return yamlErrorAt(path+".transport", "transport is required")
		default:
			return yamlErrorAt(path+".transport", "tacacs transport must be tcp or tls")
		}
	case domain.ProtocolRADIUS:
		switch transport {
		case EndpointTransportUDP:
			return nil
		case "":
			return yamlErrorAt(path+".transport", "transport is required")
		default:
			return yamlErrorAt(path+".transport", "radius transport must be udp")
		}
	default:
		return yamlErrorAt(path+".protocol", "protocol must be tacacs or radius")
	}
}

func normalizeEndpointRoles(raw []string, proto domain.Protocol, path string) ([]domain.ListenerRole, error) {
	if len(raw) == 0 {
		return nil, yamlErrorAt(path, "at least one role is required")
	}
	out := make([]domain.ListenerRole, 0, len(raw))
	seen := map[domain.ListenerRole]struct{}{}
	for i, s := range raw {
		r, err := domain.ParseListenerRole(s)
		if err != nil {
			return nil, yamlErrorAt(indexPath(path, i), "unknown listener role")
		}
		if !roleLegalForProtocol(proto, r) {
			return nil, yamlErrorAt(indexPath(path, i), "role is not legal for this protocol")
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out, nil
}

func roleLegalForProtocol(proto domain.Protocol, role domain.ListenerRole) bool {
	switch proto {
	case domain.ProtocolTACACS:
		switch role {
		case domain.RoleAuthentication, domain.RoleAuthorization, domain.RoleAccounting:
			return true
		default:
			return false
		}
	case domain.ProtocolRADIUS:
		switch role {
		case domain.RoleAccess, domain.RoleAccounting:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func normalizeTACACSEndpoint(raw *rawTACACSEndpoint, path string, allowEnv bool, flatten Client) (*TACACSEndpoint, error) {
	if raw == nil {
		// Inherit flatten policy when the tacacs: block is omitted.
		return &TACACSEndpoint{
			SharedSecret:          flatten.Legacy.SharedSecret,
			SharedSecretLifecycle: cloneSecretLifecycle(flatten.Legacy.SharedSecretLifecycle),
			AllowedMethods:        copyAuthMethods(flatten.Authentication.AllowedMethods),
			DefaultService:        flatten.Authentication.DefaultService,
			DefaultGroupIDs:       copyStrings(flatten.Authorization.DefaultGroupIDs),
			Accounting:            flatten.Accounting,
		}, nil
	}
	sec, err := normalizeSecretRef(raw.SharedSecret, credentials.PurposeLegacySharedSecret, path+".shared_secret", allowEnv)
	if err != nil {
		return nil, err
	}
	if !sec.Set() {
		sec = flatten.Legacy.SharedSecret
	}
	rot, err := parseDuration(raw.SharedSecretLifecycle.RotationInterval, path+".shared_secret_lifecycle.rotation_interval")
	if err != nil {
		return nil, err
	}
	auth, err := normalizeClientAuth(rawClientAuth{
		AllowedMethods: raw.AllowedMethods,
		DefaultService: raw.DefaultService,
	}, path)
	if err != nil {
		return nil, err
	}
	if len(auth.AllowedMethods) == 0 {
		auth = flatten.Authentication
	} else if flatten.Authentication.DefaultService != domain.AuthenServiceNone && auth.DefaultService == domain.AuthenServiceNone && raw.DefaultService == "" {
		auth.DefaultService = flatten.Authentication.DefaultService
	}
	groups := copyStrings(raw.DefaultGroupIDs)
	if len(groups) == 0 {
		groups = copyStrings(flatten.Authorization.DefaultGroupIDs)
	}
	acctEnabled := boolOr(raw.Accounting.Enabled, flatten.Accounting.Enabled)
	if raw.Accounting.Enabled == nil && raw.Accounting.AcceptStart == nil &&
		raw.Accounting.AcceptStop == nil && raw.Accounting.AcceptWatchdog == nil {
		return &TACACSEndpoint{
			SharedSecret: sec,
			SharedSecretLifecycle: SecretLifecycleMeta{
				LastRotatedAt:    cloneTime(raw.SharedSecretLifecycle.LastRotatedAt),
				RotationInterval: rot,
			},
			AllowedMethods:  auth.AllowedMethods,
			DefaultService:  auth.DefaultService,
			DefaultGroupIDs: groups,
			Accounting:      flatten.Accounting,
		}, nil
	}
	return &TACACSEndpoint{
		SharedSecret: sec,
		SharedSecretLifecycle: SecretLifecycleMeta{
			LastRotatedAt:    cloneTime(raw.SharedSecretLifecycle.LastRotatedAt),
			RotationInterval: rot,
		},
		AllowedMethods:  auth.AllowedMethods,
		DefaultService:  auth.DefaultService,
		DefaultGroupIDs: groups,
		Accounting: ClientAcct{
			Enabled:        acctEnabled,
			AcceptStart:    boolOr(raw.Accounting.AcceptStart, acctEnabled),
			AcceptStop:     boolOr(raw.Accounting.AcceptStop, acctEnabled),
			AcceptWatchdog: boolOr(raw.Accounting.AcceptWatchdog, acctEnabled),
		},
	}, nil
}

func normalizeRADIUSEndpoint(raw *rawRADIUSEndpoint, path string, allowEnv bool, access RADIUSListener, roles []domain.ListenerRole) (*RADIUSEndpoint, error) {
	if raw == nil {
		return nil, yamlErrorAt(path, "radius block is required")
	}
	sec, err := normalizeSecretRef(raw.SharedSecret, credentials.PurposeRADIUSSharedSecret, path+".shared_secret", allowEnv)
	if err != nil {
		return nil, err
	}
	rot, err := parseDuration(raw.SharedSecretLifecycle.RotationInterval, path+".shared_secret_lifecycle.rotation_interval")
	if err != nil {
		return nil, err
	}
	inheritRequire := access.MessageAuthenticator != RADIUSMessageAuthenticatorAllowMissing
	methods, err := normalizeRADIUSAuthMethods(raw.AllowedAuthenticationMethods, path+".allowed_authentication_methods")
	if err != nil {
		return nil, err
	}
	if endpointRolesContain(roles, domain.RoleAccess) && len(methods) == 0 {
		methods = []string{RADIUSAuthMethodPAP, RADIUSAuthMethodCHAP}
	}
	status, err := normalizeRADIUSStatusTypes(raw.Accounting.AcceptStatusTypes, path+".accounting.accept_status_types")
	if err != nil {
		return nil, err
	}
	if endpointRolesContain(roles, domain.RoleAccounting) && len(status) == 0 {
		status = defaultRADIUSAcceptStatusTypes()
	}
	return &RADIUSEndpoint{
		SharedSecret: sec,
		SharedSecretLifecycle: SecretLifecycleMeta{
			LastRotatedAt:    cloneTime(raw.SharedSecretLifecycle.LastRotatedAt),
			RotationInterval: rot,
		},
		RequireMessageAuthenticator:  boolOr(raw.RequireMessageAuthenticator, inheritRequire),
		LimitProxyState:              boolOr(raw.LimitProxyState, access.LimitProxyState),
		AllowedAuthenticationMethods: methods,
		AccessPolicyID:               raw.AccessPolicyID,
		AcceptStatusTypes:            status,
	}, nil
}

func endpointRolesContain(roles []domain.ListenerRole, want domain.ListenerRole) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// ParseRADIUSAuthMethods accepts pap/chap/mschapv1/mschapv2. Used by overlay writes.
func ParseRADIUSAuthMethods(raw []string) ([]string, error) {
	out, err := normalizeRADIUSAuthMethods(raw, "radius.allowed_methods")
	if err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "RADIUS authentication method must be pap, chap, mschapv1, or mschapv2").WithPath("radius.allowed_methods")
	}
	return out, nil
}

// ParseRADIUSStatusTypes accepts the MVP accounting status allowlist.
func ParseRADIUSStatusTypes(raw []string) ([]string, error) {
	out, err := normalizeRADIUSStatusTypes(raw, "radius.accept_status_types")
	if err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "unknown RADIUS accounting status type").WithPath("radius.accept_status_types")
	}
	return out, nil
}

func normalizeRADIUSAuthMethods(raw []string, path string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for i, s := range raw {
		m := strings.ToLower(strings.TrimSpace(s))
		switch m {
		case RADIUSAuthMethodPAP, RADIUSAuthMethodCHAP, RADIUSAuthMethodMSCHAPv1, RADIUSAuthMethodMSCHAPv2:
		default:
			return nil, yamlErrorAt(indexPath(path, i), "RADIUS authentication method must be pap, chap, mschapv1, or mschapv2")
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out, nil
}

func normalizeRADIUSStatusTypes(raw []string, path string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	out := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for i, s := range raw {
		v := strings.ToLower(strings.TrimSpace(s))
		if !validRADIUSAcceptStatus(v) {
			return nil, yamlErrorAt(indexPath(path, i), "unknown RADIUS accounting status type")
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

func validRADIUSAcceptStatus(s string) bool {
	switch s {
	case RADIUSAcctStart, RADIUSAcctStop, RADIUSAcctInterimUpdate, RADIUSAcctAccountingOn, RADIUSAcctAccountingOff:
		return true
	default:
		return false
	}
}

func copyAuthMethods(in []AuthMethod) []AuthMethod {
	if in == nil {
		return nil
	}
	out := make([]AuthMethod, len(in))
	copy(out, in)
	return out
}

func defaultRADIUSAcceptStatusTypes() []string {
	return []string{
		RADIUSAcctStart,
		RADIUSAcctStop,
		RADIUSAcctInterimUpdate,
		RADIUSAcctAccountingOn,
		RADIUSAcctAccountingOff,
	}
}

func tacacsEndpointsConsistent(eps []ClientEndpoint, path string) error {
	var first *TACACSEndpoint
	for i, ep := range eps {
		if ep.Protocol != domain.ProtocolTACACS || ep.TACACS == nil {
			continue
		}
		if first == nil {
			cp := *ep.TACACS
			first = &cp
			continue
		}
		if !reflect.DeepEqual(first.AllowedMethods, ep.TACACS.AllowedMethods) ||
			first.DefaultService != ep.TACACS.DefaultService ||
			!reflect.DeepEqual(first.DefaultGroupIDs, ep.TACACS.DefaultGroupIDs) ||
			first.Accounting != ep.TACACS.Accounting {
			return yamlErrorAt(indexPath(path, i), "TACACS endpoints must share authentication, authorization, and accounting policy")
		}
	}
	return nil
}

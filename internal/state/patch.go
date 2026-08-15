package state

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"golang.org/x/text/secure/precis"
)

// SecretPatch is a typed credential update. A nil *SecretPatch means omit
// (retain the effective material). Clear is an explicit null.
type SecretPatch struct {
	Clear bool
	Ref   config.SecretRef
}

// UpdateUser is a typed user patch. Omitted pointer fields are left unchanged.
type UpdateUser struct {
	DisplayName  *string
	Enabled      *bool
	Labels       *map[string]string
	GroupIDs     *[]string
	Rules        *config.RuleSet
	Login        *SecretPatch
	Challenge    *SecretPatch
	Enable       *SecretPatch
	Restrictions *config.UserRestrictions
}

// CreateUser creates a runtime user or an explicit baseline override.
type CreateUser struct {
	ID           string
	DisplayName  *string
	Enabled      *bool
	Labels       *map[string]string
	GroupIDs     *[]string
	Rules        *config.RuleSet
	Login        *SecretPatch
	Challenge    *SecretPatch
	Enable       *SecretPatch
	Restrictions *config.UserRestrictions
	Override     bool
}

// UpdateGroup is a typed group patch.
type UpdateGroup struct {
	DisplayName          *string
	Enabled              *bool
	Priority             *int
	Labels               *map[string]string
	Services             *[]config.ServiceRule
	CommandRules         *[]config.CommandRule
	DefaultCommandAction *domain.AuthorDecision
}

// CreateGroup creates a runtime group or an explicit baseline override.
type CreateGroup struct {
	ID                   string
	DisplayName          *string
	Enabled              *bool
	Priority             *int
	Labels               *map[string]string
	Services             *[]config.ServiceRule
	CommandRules         *[]config.CommandRule
	DefaultCommandAction *domain.AuthorDecision
	Override             bool
}

// UpdateClient is a typed client patch.
type UpdateClient struct {
	DisplayName           *string
	Enabled               *bool
	Priority              *int
	Labels                *map[string]string
	Match                 *config.ClientMatch
	SharedSecret          *SecretPatch
	SharedSecretLifecycle *config.SecretLifecycleMeta
	Authentication        *config.ClientAuth
	Authorization         *config.ClientAuthz
	Accounting            *config.ClientAcct
	// Endpoints replaces the canonical endpoint slice. Nil keeps the
	// current slice. Flatten TACACS/RADIUS fields sent with a
	// disagreeing slice are invalid_argument.
	Endpoints *[]config.ClientEndpoint
	// RADIUS is the flattened protocols.radius view. Nil keeps the
	// current RADIUS endpoint.
	RADIUS *RADIUSPatch
	// RADIUSSharedSecret is the RADIUS endpoint secret. Nil retains the
	// current material. Clear while a RADIUS endpoint remains is
	// RADIUS_SECRET_MISSING.
	RADIUSSharedSecret *SecretPatch
}

// RADIUSPatch is the flattened RADIUS view applied onto Endpoints.
type RADIUSPatch struct {
	SharedSecret                *SecretPatch
	SharedSecretLifecycle       *config.SecretLifecycleMeta
	Enabled                     *bool
	Roles                       []domain.ListenerRole
	RequireMessageAuthenticator *bool
	LimitProxyState             *bool
	AllowedMethods              []string
	AccessPolicyID              *string
	AcceptStatusTypes           []string
}

// CreateClient creates a runtime client or an explicit baseline override.
type CreateClient struct {
	ID                    string
	DisplayName           *string
	Enabled               *bool
	Priority              *int
	Labels                *map[string]string
	Match                 *config.ClientMatch
	SharedSecret          *SecretPatch
	SharedSecretLifecycle *config.SecretLifecycleMeta
	Authentication        *config.ClientAuth
	Authorization         *config.ClientAuthz
	Accounting            *config.ClientAcct
	Endpoints             *[]config.ClientEndpoint
	RADIUS                *RADIUSPatch
	RADIUSSharedSecret    *SecretPatch
	Override              bool
}

// CreateToken records a runtime token descriptor. Material is never stored.
type CreateToken struct {
	ID        string
	Name      string
	Scopes    []string
	Enabled   *bool
	ExpiresAt *time.Time
	Material  credentials.TokenMaterial
	Override  bool
}

// DeleteOptions controls tombstone vs reveal-baseline for override deletes.
type DeleteOptions struct {
	Tombstone bool
	ActorID   string
}

func applySecret(cur config.SecretRef, patch *SecretPatch, methodEnabled bool, path string) (config.SecretRef, error) {
	if patch == nil {
		return cur, nil
	}
	if patch.Clear || !patch.Ref.Set() {
		if methodEnabled {
			return config.SecretRef{}, domain.NewError(domain.CodeAuthMethodCredentialMissing, "enabled method is missing required credential material").WithPath(path)
		}
		return config.SecretRef{Purpose: cur.Purpose}, nil
	}
	out := patch.Ref
	if out.Purpose == "" {
		out.Purpose = cur.Purpose
	}
	return out, nil
}

func applyUserPatch(cur config.User, p UpdateUser) (config.User, error) {
	out := cloneUser(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.GroupIDs != nil {
		out.GroupIDs = cloneStrings(*p.GroupIDs)
	}
	if p.Rules != nil {
		out.Rules = cloneRuleSet(*p.Rules)
	}
	if p.Restrictions != nil {
		out.Restrictions.ClientIDs = cloneStrings(p.Restrictions.ClientIDs)
		out.Restrictions.ValidAfter = cloneTimePtr(p.Restrictions.ValidAfter)
		out.Restrictions.ValidBefore = cloneTimePtr(p.Restrictions.ValidBefore)
	}
	var err error
	// Login remains required while the user is an enabled login identity.
	// Challenge and ENABLE material are optional and may be cleared.
	if out.Credentials.Login.Verifier, err = applySecret(out.Credentials.Login.Verifier, p.Login, out.Enabled, "credentials.login.verifier"); err != nil {
		return config.User{}, err
	}
	if out.Credentials.Challenge.Secret, err = applySecret(out.Credentials.Challenge.Secret, p.Challenge, false, "credentials.challenge.secret"); err != nil {
		return config.User{}, err
	}
	if out.Credentials.Enable.Verifier, err = applySecret(out.Credentials.Enable.Verifier, p.Enable, false, "credentials.enable.verifier"); err != nil {
		return config.User{}, err
	}
	return out, nil
}

func applyGroupPatch(cur config.Group, p UpdateGroup) (config.Group, error) {
	out := cloneGroup(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Priority != nil {
		out.Priority = *p.Priority
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.Services != nil {
		out.Services = cloneServiceRules(*p.Services)
	}
	if p.CommandRules != nil {
		out.CommandRules = cloneCommandRules(*p.CommandRules)
	}
	if p.DefaultCommandAction != nil {
		out.DefaultCommandAction = *p.DefaultCommandAction
	}
	return out, nil
}

func applyClientPatch(cur config.Client, p UpdateClient) (config.Client, error) {
	out := cloneClient(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Priority != nil {
		out.Priority = *p.Priority
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.Match != nil {
		out.Match.SourceCIDRs = cloneStrings(p.Match.SourceCIDRs)
		out.Match.Transports = append([]domain.Transport(nil), p.Match.Transports...)
		out.Match.Mode = p.Match.Mode
		if out.Match.Mode == "" {
			out.Match.Mode = domain.MatchAddressAndCertificate
		}
		out.Match.Certificate.DNSSANs = cloneStrings(p.Match.Certificate.DNSSANs)
		out.Match.Certificate.IPSANs = cloneStrings(p.Match.Certificate.IPSANs)
	}
	if p.SharedSecretLifecycle != nil {
		out.Legacy.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(p.SharedSecretLifecycle.LastRotatedAt)
		out.Legacy.SharedSecretLifecycle.RotationInterval = p.SharedSecretLifecycle.RotationInterval
	}
	if p.Authentication != nil {
		out.Authentication.AllowedMethods = append([]config.AuthMethod(nil), p.Authentication.AllowedMethods...)
		out.Authentication.DefaultService = p.Authentication.DefaultService
	}
	if p.Authorization != nil {
		out.Authorization.DefaultGroupIDs = cloneStrings(p.Authorization.DefaultGroupIDs)
	}
	if p.Accounting != nil {
		out.Accounting = *p.Accounting
	}
	legacyOn := hasLegacyTransport(out.Match.Transports)
	var err error
	if out.Legacy.SharedSecret, err = applySecret(out.Legacy.SharedSecret, p.SharedSecret, legacyOn, "legacy.shared_secret"); err != nil {
		return config.Client{}, err
	}
	radiusSecret := p.RADIUSSharedSecret
	if radiusSecret == nil && p.RADIUS != nil {
		radiusSecret = p.RADIUS.SharedSecret
	}
	if p.Endpoints != nil {
		replaced := cloneEndpointSlice(*p.Endpoints)
		retainOmittedEndpointSecrets(cur, replaced)
		out.Endpoints = replaced
		if tacacsFlattenSpecified(p) && !config.TACACSProjectionMatches(out) {
			return config.Client{}, domain.NewError(domain.CodeInvalidArgument, "endpoints and flattened TACACS fields disagree").WithPath("endpoints")
		}
		if radiusFlattenDisagrees(out, p.RADIUS) {
			return config.Client{}, domain.NewError(domain.CodeInvalidArgument, "endpoints and flattened RADIUS fields disagree").WithPath("endpoints")
		}
		config.ApplyTACACSProjection(&out)
	} else {
		if p.RADIUS != nil {
			if err = applyRADIUSFlatten(&out, p.RADIUS); err != nil {
				return config.Client{}, err
			}
		}
		// Validate only re-synthesizes a throwaway compile document.
		// Persist the projection so GET/list/export endpoints stay live.
		rebuildTACACSEndpointsFromFlatten(&out)
	}
	if err = applyRADIUSSecretPatch(&out, radiusSecret); err != nil {
		return config.Client{}, err
	}
	return out, nil
}

func applyRADIUSSecretPatch(c *config.Client, patch *SecretPatch) error {
	if patch == nil {
		return nil
	}
	ep := radiusEndpointPtr(c)
	if ep == nil || ep.RADIUS == nil {
		if patch.Clear || !patch.Ref.Set() {
			return nil
		}
		return domain.NewError(domain.CodeInvalidArgument, "client has no RADIUS endpoint").WithPath("endpoints")
	}
	if patch.Clear || !patch.Ref.Set() {
		return domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS endpoint requires a shared secret").WithPath("endpoints")
	}
	out := patch.Ref
	if out.Purpose == "" {
		out.Purpose = credentials.PurposeRADIUSSharedSecret
	}
	ep.RADIUS.SharedSecret = out
	return nil
}

func radiusEndpointPtr(c *config.Client) *config.ClientEndpoint {
	if c == nil {
		return nil
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Protocol == domain.ProtocolRADIUS && c.Endpoints[i].RADIUS != nil {
			return &c.Endpoints[i]
		}
	}
	return nil
}

// rebuildTACACSEndpointsFromFlatten replaces TACACS endpoints from flatten
// fields and keeps any RADIUS endpoint. TACACS-only overlay patches must
// persist this slice; Validate's synth is not published.
func rebuildTACACSEndpointsFromFlatten(c *config.Client) {
	if c == nil {
		return
	}
	var radius []config.ClientEndpoint
	for _, ep := range c.Endpoints {
		if ep.Protocol == domain.ProtocolRADIUS {
			radius = append(radius, cloneClientEndpoint(ep))
		}
	}
	c.Endpoints = append(config.SynthesizeTACACSEndpoints(*c), radius...)
}

func hasLegacyTransport(ts []domain.Transport) bool {
	for _, t := range ts {
		if t == domain.TransportLegacy {
			return true
		}
	}
	return false
}

func tacacsFlattenSpecified(p UpdateClient) bool {
	return p.Match != nil || p.SharedSecret != nil || p.SharedSecretLifecycle != nil ||
		p.Authentication != nil || p.Authorization != nil || p.Accounting != nil
}

func radiusFlattenDisagrees(c config.Client, p *RADIUSPatch) bool {
	if p == nil {
		return false
	}
	ep := radiusEndpointPtr(&c)
	if p.Enabled != nil && !*p.Enabled {
		return ep != nil
	}
	if ep == nil || ep.RADIUS == nil {
		return true
	}
	r := ep.RADIUS
	if len(p.Roles) > 0 && !sameRoles(ep.Roles, p.Roles) {
		return true
	}
	if p.RequireMessageAuthenticator != nil && r.RequireMessageAuthenticator != *p.RequireMessageAuthenticator {
		return true
	}
	if p.LimitProxyState != nil && r.LimitProxyState != *p.LimitProxyState {
		return true
	}
	if p.AllowedMethods != nil && !sameStrings(r.AllowedAuthenticationMethods, p.AllowedMethods) {
		return true
	}
	if p.AccessPolicyID != nil && r.AccessPolicyID != *p.AccessPolicyID {
		return true
	}
	if p.AcceptStatusTypes != nil && !sameStrings(r.AcceptStatusTypes, p.AcceptStatusTypes) {
		return true
	}
	if p.SharedSecret != nil && !p.SharedSecret.Clear && p.SharedSecret.Ref.Set() {
		want := p.SharedSecret.Ref
		if want.Purpose == "" {
			want.Purpose = credentials.PurposeRADIUSSharedSecret
		}
		if r.SharedSecret.File != want.File || r.SharedSecret.Environment != want.Environment {
			return true
		}
	}
	return false
}

func applyRADIUSFlatten(c *config.Client, p *RADIUSPatch) error {
	if p == nil {
		return nil
	}
	if p.Enabled != nil && !*p.Enabled {
		c.Endpoints = removeRADIUSEndpoints(c.Endpoints)
		return nil
	}
	roles := p.Roles
	if len(roles) == 0 {
		if ep := radiusEndpointPtr(c); ep != nil && len(ep.Roles) > 0 {
			roles = append([]domain.ListenerRole(nil), ep.Roles...)
		} else {
			roles = []domain.ListenerRole{domain.RoleAccess, domain.RoleAccounting}
		}
	}
	if err := validateRADIUSRoles(roles); err != nil {
		return err
	}
	ep := radiusEndpointPtr(c)
	if ep == nil {
		if len(c.Endpoints) == 0 {
			c.Endpoints = config.SynthesizeTACACSEndpoints(*c)
		}
		rad := defaultRADIUSEndpoint(roles)
		if err := applyRADIUSFields(&rad, p); err != nil {
			return err
		}
		c.Endpoints = append(c.Endpoints, config.ClientEndpoint{
			ID:        "radius-udp",
			Protocol:  domain.ProtocolRADIUS,
			Transport: config.EndpointTransportUDP,
			Roles:     append([]domain.ListenerRole(nil), roles...),
			RADIUS:    &rad,
		})
		return nil
	}
	ep.Roles = append([]domain.ListenerRole(nil), roles...)
	return applyRADIUSFields(ep.RADIUS, p)
}

func applyRADIUSFields(rad *config.RADIUSEndpoint, p *RADIUSPatch) error {
	if rad == nil || p == nil {
		return nil
	}
	if p.SharedSecretLifecycle != nil {
		rad.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(p.SharedSecretLifecycle.LastRotatedAt)
		rad.SharedSecretLifecycle.RotationInterval = p.SharedSecretLifecycle.RotationInterval
	}
	if p.RequireMessageAuthenticator != nil {
		rad.RequireMessageAuthenticator = *p.RequireMessageAuthenticator
	}
	if p.LimitProxyState != nil {
		rad.LimitProxyState = *p.LimitProxyState
	}
	if p.AllowedMethods != nil {
		methods, err := config.ParseRADIUSAuthMethods(p.AllowedMethods)
		if err != nil {
			return err
		}
		rad.AllowedAuthenticationMethods = methods
	}
	if p.AccessPolicyID != nil {
		rad.AccessPolicyID = *p.AccessPolicyID
	}
	if p.AcceptStatusTypes != nil {
		status, err := config.ParseRADIUSStatusTypes(p.AcceptStatusTypes)
		if err != nil {
			return err
		}
		rad.AcceptStatusTypes = status
	}
	return nil
}

func defaultRADIUSEndpoint(roles []domain.ListenerRole) config.RADIUSEndpoint {
	rad := config.RADIUSEndpoint{
		RequireMessageAuthenticator: true,
		LimitProxyState:             true,
	}
	if endpointHasRole(roles, domain.RoleAccess) {
		rad.AllowedAuthenticationMethods = []string{config.RADIUSAuthMethodPAP, config.RADIUSAuthMethodCHAP}
	}
	if endpointHasRole(roles, domain.RoleAccounting) {
		rad.AcceptStatusTypes = []string{
			config.RADIUSAcctStart,
			config.RADIUSAcctStop,
			config.RADIUSAcctInterimUpdate,
			config.RADIUSAcctAccountingOn,
			config.RADIUSAcctAccountingOff,
		}
	}
	return rad
}

func validateRADIUSRoles(roles []domain.ListenerRole) error {
	if len(roles) == 0 {
		return domain.NewError(domain.CodeInvalidArgument, "RADIUS endpoint requires at least one role").WithPath("radius.roles")
	}
	for i, r := range roles {
		switch r {
		case domain.RoleAccess, domain.RoleAccounting:
		default:
			return domain.NewError(domain.CodeInvalidArgument, "RADIUS role must be access or accounting").WithPath("radius.roles").WithDetail("index", i)
		}
	}
	return nil
}

func endpointHasRole(roles []domain.ListenerRole, want domain.ListenerRole) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func removeRADIUSEndpoints(in []config.ClientEndpoint) []config.ClientEndpoint {
	if len(in) == 0 {
		return nil
	}
	out := make([]config.ClientEndpoint, 0, len(in))
	for _, ep := range in {
		if ep.Protocol == domain.ProtocolRADIUS {
			continue
		}
		out = append(out, ep)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneEndpointSlice(in []config.ClientEndpoint) []config.ClientEndpoint {
	if in == nil {
		return []config.ClientEndpoint{}
	}
	out := make([]config.ClientEndpoint, len(in))
	for i, ep := range in {
		out[i] = cloneClientEndpoint(ep)
	}
	return out
}

func retainOmittedEndpointSecrets(prev config.Client, next []config.ClientEndpoint) {
	oldByID := map[string]config.ClientEndpoint{}
	var oldRADIUS *config.RADIUSEndpoint
	var oldLegacy *config.TACACSEndpoint
	for i := range prev.Endpoints {
		ep := prev.Endpoints[i]
		oldByID[ep.ID] = ep
		if ep.Protocol == domain.ProtocolRADIUS && ep.RADIUS != nil {
			oldRADIUS = ep.RADIUS
		}
		if ep.Protocol == domain.ProtocolTACACS && ep.Transport == config.EndpointTransportTCP && ep.TACACS != nil {
			oldLegacy = ep.TACACS
		}
	}
	for i := range next {
		ep := &next[i]
		if old, ok := oldByID[ep.ID]; ok {
			retainOneEndpointSecret(ep, &old)
			continue
		}
		if ep.Protocol == domain.ProtocolRADIUS && ep.RADIUS != nil && !ep.RADIUS.SharedSecret.Set() && oldRADIUS != nil {
			ep.RADIUS.SharedSecret = cloneSecretRef(oldRADIUS.SharedSecret)
		}
		if ep.Protocol == domain.ProtocolTACACS && ep.Transport == config.EndpointTransportTCP && ep.TACACS != nil && !ep.TACACS.SharedSecret.Set() && oldLegacy != nil {
			ep.TACACS.SharedSecret = cloneSecretRef(oldLegacy.SharedSecret)
		}
	}
}

func retainOneEndpointSecret(dst, src *config.ClientEndpoint) {
	if dst == nil || src == nil {
		return
	}
	if dst.RADIUS != nil && !dst.RADIUS.SharedSecret.Set() && src.RADIUS != nil {
		dst.RADIUS.SharedSecret = cloneSecretRef(src.RADIUS.SharedSecret)
	}
	if dst.TACACS != nil && !dst.TACACS.SharedSecret.Set() && src.TACACS != nil {
		dst.TACACS.SharedSecret = cloneSecretRef(src.TACACS.SharedSecret)
	}
}

func sameRoles(a, b []domain.ListenerRole) bool {
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

func sameStrings(a, b []string) bool {
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

func userFromCreate(base *config.User, req CreateUser) (config.User, error) {
	var cur config.User
	if base != nil {
		cur = cloneUser(*base)
	} else {
		cur.Enabled = true
		cur.Credentials.Login.Verifier.Purpose = credentials.PurposeLoginVerifier
		cur.Credentials.Challenge.Secret.Purpose = credentials.PurposeChallengeSecret
		cur.Credentials.Enable.Verifier.Purpose = credentials.PurposeEnableVerifier
	}
	cur.ID = req.ID
	return applyUserPatch(cur, UpdateUser{
		DisplayName:  req.DisplayName,
		Enabled:      req.Enabled,
		Labels:       req.Labels,
		GroupIDs:     req.GroupIDs,
		Rules:        req.Rules,
		Login:        req.Login,
		Challenge:    req.Challenge,
		Enable:       req.Enable,
		Restrictions: req.Restrictions,
	})
}

func groupFromCreate(base *config.Group, req CreateGroup) (config.Group, error) {
	var cur config.Group
	if base != nil {
		cur = cloneGroup(*base)
	} else {
		cur.Enabled = true
		cur.DefaultCommandAction = domain.DecisionDeny
	}
	cur.ID = req.ID
	return applyGroupPatch(cur, UpdateGroup{
		DisplayName:          req.DisplayName,
		Enabled:              req.Enabled,
		Priority:             req.Priority,
		Labels:               req.Labels,
		Services:             req.Services,
		CommandRules:         req.CommandRules,
		DefaultCommandAction: req.DefaultCommandAction,
	})
}

func clientFromCreate(base *config.Client, req CreateClient) (config.Client, error) {
	var cur config.Client
	if base != nil {
		cur = cloneClient(*base)
	} else {
		cur.Enabled = true
		cur.Match.Mode = domain.MatchAddressAndCertificate
		cur.Legacy.SharedSecret.Purpose = credentials.PurposeLegacySharedSecret
		cur.Accounting.Enabled = true
		cur.Accounting.AcceptStart = true
		cur.Accounting.AcceptStop = true
		cur.Accounting.AcceptWatchdog = true
	}
	cur.ID = req.ID
	return applyClientPatch(cur, UpdateClient{
		DisplayName:           req.DisplayName,
		Enabled:               req.Enabled,
		Priority:              req.Priority,
		Labels:                req.Labels,
		Match:                 req.Match,
		SharedSecret:          req.SharedSecret,
		SharedSecretLifecycle: req.SharedSecretLifecycle,
		Authentication:        req.Authentication,
		Authorization:         req.Authorization,
		Accounting:            req.Accounting,
		Endpoints:             req.Endpoints,
		RADIUS:                req.RADIUS,
		RADIUSSharedSecret:    req.RADIUSSharedSecret,
	})
}

func normalizeUserID(id string) (string, error) {
	if id == "" {
		return "", domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath("id")
	}
	out, err := precis.UsernameCasePreserved.String(id)
	if err != nil || out == "" {
		return "", domain.NewError(domain.CodeInvalidArgument, "id is not a valid UsernameCasePreserved identifier").WithPath("id")
	}
	return out, nil
}

func requireID(id, path string) error {
	if id == "" {
		return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(path)
	}
	return nil
}

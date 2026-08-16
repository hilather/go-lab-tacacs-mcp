package operations

import (
	"sort"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func userView(u state.EffectiveUser, rev domain.Revision) User {
	meta := u.Meta.WithSnapshotRevision(rev)
	return User{
		ID:                  u.User.ID,
		DisplayName:         u.User.DisplayName,
		Enabled:             u.User.Enabled,
		Source:              meta.Source,
		ShadowsSource:       meta.ShadowsSource,
		Deleted:             meta.Deleted,
		RevisionCreated:     meta.RevisionCreated,
		RevisionUpdated:     meta.RevisionUpdated,
		EffectiveRevision:   meta.EffectiveRevision,
		Labels:              cloneLabels(u.User.Labels),
		GroupIDs:            cloneStrings(u.User.GroupIDs),
		Rules:               ruleSetView(u.User.Rules),
		Restrictions:        restrictionsView(u.User.Restrictions),
		ASCIIPapConfigured:  u.Capabilities.Login,
		ChallengeConfigured: u.Capabilities.Challenge,
		EnableConfigured:    u.Capabilities.Enable,
		MustChangeLogin:     u.User.MustChangeLogin,
		MustChangeEnable:    u.User.MustChangeEnable,
		RADIUSPolicyID:      u.User.RADIUSPolicyID,
		CreatedAt:           meta.CreatedAt,
		UpdatedAt:           meta.UpdatedAt,
	}
}

func groupView(g state.EffectiveGroup, rev domain.Revision) Group {
	meta := g.Meta.WithSnapshotRevision(rev)
	action := string(g.Group.DefaultCommandAction)
	if action == string(domain.DecisionDeny) {
		action = ""
	}
	return Group{
		ID:                   g.Group.ID,
		DisplayName:          g.Group.DisplayName,
		Enabled:              g.Group.Enabled,
		Priority:             g.Group.Priority,
		Source:               meta.Source,
		ShadowsSource:        meta.ShadowsSource,
		Deleted:              meta.Deleted,
		RevisionCreated:      meta.RevisionCreated,
		RevisionUpdated:      meta.RevisionUpdated,
		EffectiveRevision:    meta.EffectiveRevision,
		Labels:               cloneLabels(g.Group.Labels),
		Services:             serviceViews(g.Group.Services),
		CommandRules:         commandViews(g.Group.CommandRules),
		DefaultCommandAction: action,
		RADIUSPolicyID:       g.Group.RADIUSPolicyID,
		CreatedAt:            meta.CreatedAt,
		UpdatedAt:            meta.UpdatedAt,
	}
}

func clientView(c state.EffectiveClient, rev domain.Revision) Client {
	meta := c.Meta.WithSnapshotRevision(rev)
	life := string(c.Lifecycle)
	if life == "" {
		life = string(domain.LifecycleUnknown)
	}
	return Client{
		ID:                     c.Client.ID,
		DisplayName:            c.Client.DisplayName,
		Enabled:                c.Client.Enabled,
		Priority:               c.Client.Priority,
		Source:                 meta.Source,
		ShadowsSource:          meta.ShadowsSource,
		Deleted:                meta.Deleted,
		RevisionCreated:        meta.RevisionCreated,
		RevisionUpdated:        meta.RevisionUpdated,
		EffectiveRevision:      meta.EffectiveRevision,
		Labels:                 cloneLabels(c.Client.Labels),
		Match:                  clientMatchView(c.Client.Match),
		SharedSecretConfigured: c.Client.Legacy.SharedSecret.Set(),
		SharedSecretLifecycle:  life,
		Authentication:         clientAuthView(c.Client.Authentication),
		Authorization:          clientAuthzView(c.Client.Authorization),
		Accounting:             clientAcctView(c.Client.Accounting),
		Protocols:              clientProtocolsView(c),
		Endpoints:              clientEndpointViews(c.Client, c.RADIUSLifecycle),
		CreatedAt:              meta.CreatedAt,
		UpdatedAt:              meta.UpdatedAt,
	}
}

func deletedView(t domain.Tombstone, rev domain.Revision) (id string, meta domain.ObjectMeta) {
	return string(t.ID), domain.ObjectMeta{
		ID:                t.ID,
		Kind:              t.Kind,
		Source:            domain.SourceConfig,
		Deleted:           true,
		RevisionCreated:   t.AtRevision,
		RevisionUpdated:   t.AtRevision,
		EffectiveRevision: rev,
		CreatedAt:         t.At,
		UpdatedAt:         t.At,
	}
}

func deletedUser(t domain.Tombstone, rev domain.Revision) User {
	id, meta := deletedView(t, rev)
	return User{ID: id, Source: meta.Source, Deleted: true, RevisionCreated: meta.RevisionCreated, RevisionUpdated: meta.RevisionUpdated, EffectiveRevision: rev, CreatedAt: meta.CreatedAt, UpdatedAt: meta.UpdatedAt}
}

func deletedGroup(t domain.Tombstone, rev domain.Revision) Group {
	id, meta := deletedView(t, rev)
	return Group{ID: id, Source: meta.Source, Deleted: true, RevisionCreated: meta.RevisionCreated, RevisionUpdated: meta.RevisionUpdated, EffectiveRevision: rev, CreatedAt: meta.CreatedAt, UpdatedAt: meta.UpdatedAt}
}

func deletedClient(t domain.Tombstone, rev domain.Revision) Client {
	id, meta := deletedView(t, rev)
	return Client{ID: id, Source: meta.Source, Deleted: true, SharedSecretLifecycle: string(domain.LifecycleUnknown), RevisionCreated: meta.RevisionCreated, RevisionUpdated: meta.RevisionUpdated, EffectiveRevision: rev, CreatedAt: meta.CreatedAt, UpdatedAt: meta.UpdatedAt}
}

func findTombstone(snap *state.Snapshot, kind domain.ObjectKind, id string) (domain.Tombstone, bool) {
	if snap == nil {
		return domain.Tombstone{}, false
	}
	for _, t := range snap.Tombstones() {
		if t.Kind == kind && string(t.ID) == id {
			return t, true
		}
	}
	return domain.Tombstone{}, false
}

func tombstonesOf(snap *state.Snapshot, kind domain.ObjectKind) []domain.Tombstone {
	if snap == nil {
		return nil
	}
	var out []domain.Tombstone
	for _, t := range snap.Tombstones() {
		if t.Kind == kind {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].ID) < string(out[j].ID) })
	return out
}

func ruleSetView(r config.RuleSet) RuleSetView {
	return RuleSetView{Services: serviceViews(r.Services), CommandRules: commandViews(r.CommandRules)}
}

func serviceViews(in []config.ServiceRule) []ServiceRuleView {
	if len(in) == 0 {
		return nil
	}
	out := make([]ServiceRuleView, 0, len(in))
	for _, r := range in {
		out = append(out, ServiceRuleView{
			Service:         r.Service,
			Protocol:        cloneStringPtr(r.Protocol),
			Action:          string(r.Action),
			ReplyAttributes: avViews(r.ReplyAttributes),
		})
	}
	return out
}

func commandViews(in []config.CommandRule) []CommandRuleView {
	if len(in) == 0 {
		return nil
	}
	out := make([]CommandRuleView, 0, len(in))
	for _, r := range in {
		out = append(out, CommandRuleView{
			ID:        r.ID,
			Priority:  r.Priority,
			Action:    string(r.Action),
			Command:   MatchView{Exact: r.Command.Exact, Pattern: r.Command.Pattern},
			Arguments: MatchView{Exact: r.Arguments.Exact, Pattern: r.Arguments.Pattern},
			Reason:    r.Reason,
		})
	}
	return out
}

func avViews(in domain.AVPairs) []PolicyTraceAV {
	if len(in) == 0 {
		return nil
	}
	out := make([]PolicyTraceAV, 0, len(in))
	for _, a := range in {
		sep := string(a.Separator)
		if sep == "" {
			sep = "="
		}
		out = append(out, PolicyTraceAV{Name: a.Name, Separator: sep, Value: a.Value})
	}
	return out
}

func restrictionsView(r config.UserRestrictions) RestrictionsView {
	return RestrictionsView{
		ClientIDs:   cloneStrings(r.ClientIDs),
		ValidAfter:  cloneTimePtr(r.ValidAfter),
		ValidBefore: cloneTimePtr(r.ValidBefore),
	}
}

func clientMatchView(m config.ClientMatch) ClientMatchView {
	ts := make([]string, 0, len(m.Transports))
	for _, t := range m.Transports {
		ts = append(ts, string(t))
	}
	return ClientMatchView{
		SourceCIDRs: cloneStrings(m.SourceCIDRs),
		Transports:  ts,
		Mode:        string(m.Mode),
		Certificate: CertMatchView{DNSSANs: cloneStrings(m.Certificate.DNSSANs), IPSANs: cloneStrings(m.Certificate.IPSANs)},
	}
}

func clientAuthView(a config.ClientAuth) ClientAuthView {
	methods := make([]string, 0, len(a.AllowedMethods))
	for _, m := range a.AllowedMethods {
		methods = append(methods, string(m))
	}
	svc := ""
	if a.DefaultService != 0 {
		svc = a.DefaultService.String()
	}
	return ClientAuthView{AllowedMethods: methods, DefaultService: svc}
}

func clientAuthzView(a config.ClientAuthz) ClientAuthzView {
	return ClientAuthzView{DefaultGroupIDs: cloneStrings(a.DefaultGroupIDs)}
}

func clientAcctView(a config.ClientAcct) ClientAcctView {
	return ClientAcctView{Enabled: a.Enabled, AcceptStart: a.AcceptStart, AcceptStop: a.AcceptStop, AcceptWatchdog: a.AcceptWatchdog}
}

func clientProtocolsView(c state.EffectiveClient) ClientProtocolsView {
	return ClientProtocolsView{
		TACACS: ClientTACACSProtocolView{
			LegacyEnabled:          hasTransport(c.Client.Match.Transports, domain.TransportLegacy),
			TLSEnabled:             hasTransport(c.Client.Match.Transports, domain.TransportTLS),
			SharedSecretConfigured: c.Client.Legacy.SharedSecret.Set(),
		},
		RADIUS: clientRADIUSView(c.Client, c.RADIUSLifecycle),
	}
}

func clientRADIUSView(c config.Client, life domain.SecretLifecycle) ClientRADIUSProtocolView {
	return radiusProtocolView(radiusEndpointOf(c), life)
}

func radiusProtocolView(ep *config.ClientEndpoint, life domain.SecretLifecycle) ClientRADIUSProtocolView {
	if ep == nil || ep.RADIUS == nil {
		return ClientRADIUSProtocolView{}
	}
	st := string(life)
	if st == "" {
		st = string(domain.LifecycleUnknown)
	}
	return ClientRADIUSProtocolView{
		Enabled:                     true,
		Roles:                       rolesToStrings(ep.Roles),
		SharedSecretConfigured:      ep.RADIUS.SharedSecret.Set(),
		SecretLifecycle:             st,
		RequireMessageAuthenticator: ep.RADIUS.RequireMessageAuthenticator,
		LimitProxyState:             ep.RADIUS.LimitProxyState,
		AllowedMethods:              cloneStrings(ep.RADIUS.AllowedAuthenticationMethods),
		AccessPolicyID:              ep.RADIUS.AccessPolicyID,
		AcceptStatusTypes:           cloneStrings(ep.RADIUS.AcceptStatusTypes),
		NASCoAPort:                  ep.RADIUS.NASCoAPort,
		CoADestination:              ep.RADIUS.CoADestination,
	}
}

func clientEndpointViews(c config.Client, radLife domain.SecretLifecycle) []ClientEndpointView {
	if len(c.Endpoints) == 0 {
		return nil
	}
	out := make([]ClientEndpointView, 0, len(c.Endpoints))
	for _, ep := range c.Endpoints {
		item := ClientEndpointView{
			ID:        ep.ID,
			Protocol:  string(ep.Protocol),
			Transport: ep.Transport,
			Roles:     rolesToStrings(ep.Roles),
		}
		if ep.TACACS != nil {
			svc := ""
			if ep.TACACS.DefaultService != 0 {
				svc = ep.TACACS.DefaultService.String()
			}
			methods := make([]string, 0, len(ep.TACACS.AllowedMethods))
			for _, m := range ep.TACACS.AllowedMethods {
				methods = append(methods, string(m))
			}
			item.TACACS = &ClientTACACSEndpointView{
				SharedSecretConfigured: ep.TACACS.SharedSecret.Set(),
				AllowedMethods:         methods,
				DefaultService:         svc,
				DefaultGroupIDs:        cloneStrings(ep.TACACS.DefaultGroupIDs),
				Accounting:             clientAcctView(ep.TACACS.Accounting),
			}
		}
		if ep.RADIUS != nil {
			rad := radiusProtocolView(&ep, radLife)
			item.RADIUS = &rad
		}
		out = append(out, item)
	}
	return out
}

func radiusEndpointOf(c config.Client) *config.ClientEndpoint {
	// Flatten view is the UDP RADIUS endpoint only (DAC / overlay).
	for i := range c.Endpoints {
		ep := &c.Endpoints[i]
		if ep.Protocol == domain.ProtocolRADIUS && ep.RADIUS != nil && ep.Transport == config.EndpointTransportUDP {
			return ep
		}
	}
	return nil
}

func hasTransport(ts []domain.Transport, want domain.Transport) bool {
	for _, t := range ts {
		if t == want {
			return true
		}
	}
	return false
}

func rolesToStrings(in []domain.ListenerRole) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	return out
}

func (s OptionalSecret) patch() *state.SecretPatch {
	if !s.Present {
		return nil
	}
	if s.Clear {
		return &state.SecretPatch{Clear: true}
	}
	return &state.SecretPatch{Ref: config.SecretRef{File: s.File, Environment: s.Environment}}
}

func ruleSetFromView(v *RuleSetView) (*config.RuleSet, error) {
	if v == nil {
		return nil, nil
	}
	svcs, err := serviceRulesFromView(v.Services)
	if err != nil {
		return nil, err
	}
	cmds, err := commandRulesFromView(v.CommandRules)
	if err != nil {
		return nil, err
	}
	return &config.RuleSet{Services: svcs, CommandRules: cmds}, nil
}

func serviceRulesFromView(in []ServiceRuleView) ([]config.ServiceRule, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]config.ServiceRule, 0, len(in))
	for i, r := range in {
		action, err := parseWireAction(r.Action, "services")
		if err != nil {
			return nil, err.(domain.Error).WithDetail("index", i)
		}
		out = append(out, config.ServiceRule{
			Service:         r.Service,
			Protocol:        cloneStringPtr(r.Protocol),
			Action:          action,
			ReplyAttributes: avsFromTrace(r.ReplyAttributes),
		})
	}
	return out, nil
}

func commandRulesFromView(in []CommandRuleView) ([]config.CommandRule, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]config.CommandRule, 0, len(in))
	for i, r := range in {
		action, err := parseWireAction(r.Action, "command_rules")
		if err != nil {
			return nil, err.(domain.Error).WithDetail("index", i)
		}
		out = append(out, config.CommandRule{
			ID:        r.ID,
			Priority:  r.Priority,
			Action:    action,
			Command:   config.StringMatch{Exact: r.Command.Exact, Pattern: r.Command.Pattern},
			Arguments: config.StringMatch{Exact: r.Arguments.Exact, Pattern: r.Arguments.Pattern},
			Reason:    r.Reason,
		})
	}
	return out, nil
}

func parseWireAction(s, path string) (domain.AuthorDecision, error) {
	d, err := domain.ParseAuthorDecision(s)
	if err != nil {
		return "", domain.NewError(domain.CodeInvalidArgument, "action must be permit_add, permit_replace, or deny").WithPath(path)
	}
	return d, nil
}

func restrictionsFromView(v *RestrictionsView) *config.UserRestrictions {
	if v == nil {
		return nil
	}
	return &config.UserRestrictions{
		ClientIDs:   cloneStrings(v.ClientIDs),
		ValidAfter:  cloneTimePtr(v.ValidAfter),
		ValidBefore: cloneTimePtr(v.ValidBefore),
	}
}

func clientMatchFromView(v *ClientMatchView) (*config.ClientMatch, error) {
	if v == nil {
		return nil, nil
	}
	var ts []domain.Transport
	for i, raw := range v.Transports {
		t, err := domain.ParseTransport(raw)
		if err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown transport").WithPath("match.transports").WithDetail("index", i)
		}
		ts = append(ts, t)
	}
	mode := domain.MatchMode(v.Mode)
	if v.Mode != "" && !mode.Valid() {
		return nil, domain.NewError(domain.CodeInvalidArgument, "unknown match mode").WithPath("match.mode")
	}
	return &config.ClientMatch{
		SourceCIDRs: cloneStrings(v.SourceCIDRs),
		Transports:  ts,
		Mode:        mode,
		Certificate: config.CertMatch{DNSSANs: cloneStrings(v.Certificate.DNSSANs), IPSANs: cloneStrings(v.Certificate.IPSANs)},
	}, nil
}

func clientAuthFromView(v *ClientAuthView) (*config.ClientAuth, error) {
	if v == nil {
		return nil, nil
	}
	var methods []config.AuthMethod
	for i, raw := range v.AllowedMethods {
		m := config.AuthMethod(raw)
		switch m {
		case config.AuthMethodASCII, config.AuthMethodPAP, config.AuthMethodCHAP, config.AuthMethodMSCHAPv1, config.AuthMethodMSCHAPv2, config.AuthMethodEnable, config.AuthMethodASCIIChpass:
			methods = append(methods, m)
		default:
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown authentication method").WithPath("authentication.allowed_methods").WithDetail("index", i)
		}
	}
	var svc domain.AuthenService
	if v.DefaultService != "" {
		parsed, err := domain.ParseAuthenService(v.DefaultService)
		if err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown default service").WithPath("authentication.default_service")
		}
		svc = parsed
	}
	return &config.ClientAuth{AllowedMethods: methods, DefaultService: svc}, nil
}

func clientAuthzFromView(v *ClientAuthzView) *config.ClientAuthz {
	if v == nil {
		return nil
	}
	return &config.ClientAuthz{DefaultGroupIDs: cloneStrings(v.DefaultGroupIDs)}
}

func clientAcctFromView(v *ClientAcctView) *config.ClientAcct {
	if v == nil {
		return nil
	}
	return &config.ClientAcct{Enabled: v.Enabled, AcceptStart: v.AcceptStart, AcceptStop: v.AcceptStop, AcceptWatchdog: v.AcceptWatchdog}
}

func clientEndpointsFromView(in *[]ClientEndpointWrite) (*[]config.ClientEndpoint, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]config.ClientEndpoint, 0, len(*in))
	seen := map[string]struct{}{}
	var radiusUDP, radiusTLS int
	for i, raw := range *in {
		ep, err := clientEndpointFromWrite(raw, i)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[ep.ID]; ok {
			return nil, domain.NewError(domain.CodeInvalidArgument, "duplicate endpoint id").WithPath("endpoints").WithDetail("index", i)
		}
		seen[ep.ID] = struct{}{}
		if ep.Protocol == domain.ProtocolRADIUS {
			switch ep.Transport {
			case config.EndpointTransportUDP:
				radiusUDP++
				if radiusUDP > 1 {
					return nil, domain.NewError(domain.CodeInvalidArgument, "a client may have at most one RADIUS UDP endpoint").WithPath("endpoints").WithDetail("index", i)
				}
			case config.EndpointTransportTLS:
				radiusTLS++
				if radiusTLS > 1 {
					return nil, domain.NewError(domain.CodeInvalidArgument, "a client may have at most one RADIUS TLS endpoint").WithPath("endpoints").WithDetail("index", i)
				}
			}
		}
		out = append(out, ep)
	}
	return &out, nil
}

func clientEndpointFromWrite(raw ClientEndpointWrite, index int) (config.ClientEndpoint, error) {
	path := "endpoints"
	if raw.ID == "" {
		return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(path).WithDetail("index", index)
	}
	proto, err := domain.ParseProtocol(raw.Protocol)
	if err != nil || proto == domain.ProtocolHTTP {
		return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "protocol must be tacacs or radius").WithPath(path).WithDetail("index", index)
	}
	transport := raw.Transport
	switch proto {
	case domain.ProtocolTACACS:
		if transport != config.EndpointTransportTCP && transport != config.EndpointTransportTLS {
			return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "tacacs transport must be tcp or tls").WithPath(path).WithDetail("index", index)
		}
	case domain.ProtocolRADIUS:
		if transport != config.EndpointTransportUDP && transport != config.EndpointTransportTLS {
			return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "radius transport must be udp or tls").WithPath(path).WithDetail("index", index)
		}
	}
	roles, err := listenerRolesFromView(raw.Roles, proto, path)
	if err != nil {
		return config.ClientEndpoint{}, wrapRoleErr(err, index)
	}
	if len(roles) == 0 {
		return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "at least one role is required").WithPath(path).WithDetail("index", index)
	}
	if raw.TACACS != nil && raw.RADIUS != nil {
		return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "endpoint must set exactly one of tacacs or radius").WithPath(path).WithDetail("index", index)
	}
	ep := config.ClientEndpoint{ID: raw.ID, Protocol: proto, Transport: transport, Roles: roles}
	switch proto {
	case domain.ProtocolTACACS:
		if raw.RADIUS != nil {
			return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "radius block is not valid on a tacacs endpoint").WithPath(path).WithDetail("index", index)
		}
		tac, err := tacacsEndpointFromWrite(raw.TACACS)
		if err != nil {
			return config.ClientEndpoint{}, err
		}
		ep.TACACS = tac
	case domain.ProtocolRADIUS:
		if raw.TACACS != nil {
			return config.ClientEndpoint{}, domain.NewError(domain.CodeInvalidArgument, "tacacs block is not valid on a radius endpoint").WithPath(path).WithDetail("index", index)
		}
		rad, err := radiusEndpointFromWrite(raw.RADIUS, roles)
		if err != nil {
			return config.ClientEndpoint{}, err
		}
		ep.RADIUS = rad
	}
	return ep, nil
}

func tacacsEndpointFromWrite(v *ClientTACACSEndpointWrite) (*config.TACACSEndpoint, error) {
	if v == nil {
		return &config.TACACSEndpoint{}, nil
	}
	auth, err := clientAuthFromView(&ClientAuthView{AllowedMethods: v.AllowedMethods, DefaultService: v.DefaultService})
	if err != nil {
		return nil, err
	}
	if auth == nil {
		auth = &config.ClientAuth{}
	}
	life, err := lifecycleFromView(v.SharedSecretLifecycle)
	if err != nil {
		return nil, err
	}
	if life == nil {
		life = &config.SecretLifecycleMeta{}
	}
	tac := &config.TACACSEndpoint{
		AllowedMethods:        auth.AllowedMethods,
		DefaultService:        auth.DefaultService,
		DefaultGroupIDs:       cloneStrings(v.DefaultGroupIDs),
		SharedSecretLifecycle: *life,
	}
	if v.Accounting != nil {
		tac.Accounting = *clientAcctFromView(v.Accounting)
	}
	if patch := v.SharedSecret.patch(); patch != nil && !patch.Clear && patch.Ref.Set() {
		tac.SharedSecret = patch.Ref
		if tac.SharedSecret.Purpose == "" {
			tac.SharedSecret.Purpose = credentials.PurposeLegacySharedSecret
		}
	}
	return tac, nil
}

func radiusEndpointFromWrite(v *ClientRADIUSWrite, roles []domain.ListenerRole) (*config.RADIUSEndpoint, error) {
	if v == nil {
		rad := &config.RADIUSEndpoint{
			RequireMessageAuthenticator:  true,
			LimitProxyState:              true,
			AllowedAuthenticationMethods: config.FillRADIUSAccessMethods(nil, roles),
		}
		return rad, nil
	}
	methods, err := config.ParseRADIUSAuthMethods(v.AllowedMethods)
	if err != nil {
		return nil, err
	}
	methods = config.DefaultRADIUSAccessMethods(methods, roles)
	status, err := config.ParseRADIUSStatusTypes(v.AcceptStatusTypes)
	if err != nil {
		return nil, err
	}
	rad := &config.RADIUSEndpoint{
		RequireMessageAuthenticator:  true,
		LimitProxyState:              true,
		AllowedAuthenticationMethods: config.FillRADIUSAccessMethods(methods, roles),
		AcceptStatusTypes:            status,
	}
	if v.AccessPolicyID != nil {
		rad.AccessPolicyID = *v.AccessPolicyID
	}
	if v.RequireMessageAuthenticator != nil {
		rad.RequireMessageAuthenticator = *v.RequireMessageAuthenticator
	}
	if v.LimitProxyState != nil {
		rad.LimitProxyState = *v.LimitProxyState
	}
	life, err := lifecycleFromView(v.SharedSecretLifecycle)
	if err != nil {
		return nil, err
	}
	if life != nil {
		rad.SharedSecretLifecycle = *life
	}
	if patch := v.SharedSecret.patch(); patch != nil && !patch.Clear && patch.Ref.Set() {
		rad.SharedSecret = patch.Ref
		if rad.SharedSecret.Purpose == "" {
			rad.SharedSecret.Purpose = credentials.PurposeRADIUSSharedSecret
		}
	}
	if v.NASCoAPort != nil {
		rad.NASCoAPort = *v.NASCoAPort
	} else {
		rad.NASCoAPort = config.DefaultNASCoAPort
	}
	if v.CoADestination != nil {
		rad.CoADestination = *v.CoADestination
	}
	return rad, nil
}

func radiusPatchFromView(v *ClientRADIUSWrite) (*state.RADIUSPatch, error) {
	if v == nil {
		return nil, nil
	}
	roles, err := listenerRolesFromView(v.Roles, domain.ProtocolRADIUS, "radius.roles")
	if err != nil {
		return nil, err
	}
	life, err := lifecycleFromView(v.SharedSecretLifecycle)
	if err != nil {
		return nil, err
	}
	methods, err := config.ParseRADIUSAuthMethods(v.AllowedMethods)
	if err != nil {
		return nil, err
	}
	status, err := config.ParseRADIUSStatusTypes(v.AcceptStatusTypes)
	if err != nil {
		return nil, err
	}
	return &state.RADIUSPatch{
		SharedSecret:                v.SharedSecret.patch(),
		SharedSecretLifecycle:       life,
		Enabled:                     v.Enabled,
		Roles:                       roles,
		RequireMessageAuthenticator: v.RequireMessageAuthenticator,
		LimitProxyState:             v.LimitProxyState,
		AllowedMethods:              methods,
		AccessPolicyID:              v.AccessPolicyID,
		AcceptStatusTypes:           status,
	}, nil
}

func listenerRolesFromView(in []string, proto domain.Protocol, path string) ([]domain.ListenerRole, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]domain.ListenerRole, 0, len(in))
	seen := map[domain.ListenerRole]struct{}{}
	for i, raw := range in {
		r, err := domain.ParseListenerRole(raw)
		if err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown listener role").WithPath(path).WithDetail("index", i)
		}
		if !roleLegalForProtocol(proto, r) {
			return nil, domain.NewError(domain.CodeInvalidArgument, "role is not legal for this protocol").WithPath(path).WithDetail("index", i)
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out, nil
}

func wrapRoleErr(err error, index int) error {
	if de, ok := domain.AsError(err); ok {
		return de.WithDetail("index", index)
	}
	return err
}

func roleLegalForProtocol(proto domain.Protocol, role domain.ListenerRole) bool {
	switch proto {
	case domain.ProtocolTACACS:
		return role == domain.RoleAuthentication || role == domain.RoleAuthorization || role == domain.RoleAccounting
	case domain.ProtocolRADIUS:
		return role == domain.RoleAccess || role == domain.RoleAccounting
	default:
		return false
	}
}

func lifecycleFromView(v *LifecycleWrite) (*config.SecretLifecycleMeta, error) {
	if v == nil {
		return nil, nil
	}
	meta := &config.SecretLifecycleMeta{LastRotatedAt: cloneTimePtr(v.LastRotatedAt)}
	if v.RotationInterval != "" {
		d, err := time.ParseDuration(v.RotationInterval)
		if err != nil {
			return nil, domain.NewError(domain.CodeInvalidArgument, "invalid rotation_interval").WithPath("shared_secret_lifecycle.rotation_interval")
		}
		meta.RotationInterval = d
	}
	return meta, nil
}

func defaultCommandAction(s *string) (*domain.AuthorDecision, error) {
	if s == nil {
		return nil, nil
	}
	if *s == "" {
		d := domain.DecisionDeny
		return &d, nil
	}
	d, err := domain.ParseAuthorDecision(*s)
	if err != nil || d != domain.DecisionDeny {
		return nil, domain.NewError(domain.CodeInvalidArgument, "default_command_action must be deny").WithPath("default_command_action")
	}
	return &d, nil
}

func normalizePage(limit int) int {
	if limit <= 0 {
		return defaultObjectPage
	}
	if limit > maxObjectPage {
		return maxObjectPage
	}
	return limit
}

func pageAfter(ids []string, cursor string, limit int) (start, end int, next *string) {
	start = 0
	if cursor != "" {
		start = len(ids)
		for i, id := range ids {
			if id > cursor {
				start = i
				break
			}
		}
	}
	end = start + limit
	if end > len(ids) {
		end = len(ids)
	}
	if end < len(ids) && end > start {
		c := ids[end-1]
		next = &c
	}
	return start, end, next
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	t := in.UTC()
	return &t
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	s := *in
	return &s
}

func requireID(id string) error {
	if id == "" {
		return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath("id")
	}
	return nil
}

func requireState(deps Deps) error {
	if deps.State == nil {
		return domain.NewError(domain.CodeUnavailable, "state manager is not configured")
	}
	return nil
}

func audit(deps Deps, typ, result string, rev domain.Revision) {
	if deps.Events == nil {
		return
	}
	deps.Events.Accept(events.Event{Category: events.CategoryAPI, Type: typ, Result: result, Revision: rev})
}

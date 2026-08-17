package state

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func cloneLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneSecretRef(r config.SecretRef) config.SecretRef { return r }

func cloneSecretBag(in map[string][]byte) map[string][]byte {
	if len(in) == 0 {
		return map[string][]byte{}
	}
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func cloneRuleSet(r config.RuleSet) config.RuleSet {
	return config.RuleSet{
		Services:     cloneServiceRules(r.Services),
		CommandRules: cloneCommandRules(r.CommandRules),
	}
}

func cloneServiceRules(in []config.ServiceRule) []config.ServiceRule {
	if in == nil {
		return nil
	}
	out := make([]config.ServiceRule, len(in))
	for i, r := range in {
		out[i] = r
		if r.Protocol != nil {
			v := *r.Protocol
			out[i].Protocol = &v
		}
		if r.ReplyAttributes != nil {
			out[i].ReplyAttributes = append(domain.AVPairs(nil), r.ReplyAttributes...)
		}
	}
	return out
}

func cloneCommandRules(in []config.CommandRule) []config.CommandRule {
	if in == nil {
		return nil
	}
	out := make([]config.CommandRule, len(in))
	copy(out, in)
	return out
}

func cloneUser(u config.User) config.User {
	out := u
	out.Labels = cloneLabels(u.Labels)
	out.GroupIDs = cloneStrings(u.GroupIDs)
	out.Rules = cloneRuleSet(u.Rules)
	out.Credentials.Login.Verifier = cloneSecretRef(u.Credentials.Login.Verifier)
	out.Credentials.Challenge.Secret = cloneSecretRef(u.Credentials.Challenge.Secret)
	out.Credentials.Enable.Verifier = cloneSecretRef(u.Credentials.Enable.Verifier)
	out.Restrictions.ClientIDs = cloneStrings(u.Restrictions.ClientIDs)
	out.Restrictions.ValidAfter = cloneTimePtr(u.Restrictions.ValidAfter)
	out.Restrictions.ValidBefore = cloneTimePtr(u.Restrictions.ValidBefore)
	return out
}

func cloneGroup(g config.Group) config.Group {
	out := g
	out.Labels = cloneLabels(g.Labels)
	out.Services = cloneServiceRules(g.Services)
	out.CommandRules = cloneCommandRules(g.CommandRules)
	return out
}

func cloneClient(c config.Client) config.Client {
	out := c
	out.Labels = cloneLabels(c.Labels)
	out.Match.SourceCIDRs = cloneStrings(c.Match.SourceCIDRs)
	out.Match.Transports = append([]domain.Transport(nil), c.Match.Transports...)
	out.Match.Certificate.DNSSANs = cloneStrings(c.Match.Certificate.DNSSANs)
	out.Match.Certificate.IPSANs = cloneStrings(c.Match.Certificate.IPSANs)
	out.Legacy.SharedSecret = cloneSecretRef(c.Legacy.SharedSecret)
	out.Legacy.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(c.Legacy.SharedSecretLifecycle.LastRotatedAt)
	out.Authentication.AllowedMethods = append([]config.AuthMethod(nil), c.Authentication.AllowedMethods...)
	out.Authorization.DefaultGroupIDs = cloneStrings(c.Authorization.DefaultGroupIDs)
	if c.Endpoints != nil {
		out.Endpoints = make([]config.ClientEndpoint, len(c.Endpoints))
		for i, ep := range c.Endpoints {
			out.Endpoints[i] = cloneClientEndpoint(ep)
		}
	}
	return out
}

func cloneClientEndpoint(ep config.ClientEndpoint) config.ClientEndpoint {
	out := ep
	out.Roles = append([]domain.ListenerRole(nil), ep.Roles...)
	if ep.TACACS != nil {
		tac := *ep.TACACS
		tac.SharedSecret = cloneSecretRef(ep.TACACS.SharedSecret)
		tac.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(ep.TACACS.SharedSecretLifecycle.LastRotatedAt)
		tac.AllowedMethods = append([]config.AuthMethod(nil), ep.TACACS.AllowedMethods...)
		tac.DefaultGroupIDs = cloneStrings(ep.TACACS.DefaultGroupIDs)
		out.TACACS = &tac
	}
	if ep.RADIUS != nil {
		rad := *ep.RADIUS
		rad.SharedSecret = cloneSecretRef(ep.RADIUS.SharedSecret)
		rad.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(ep.RADIUS.SharedSecretLifecycle.LastRotatedAt)
		rad.AllowedAuthenticationMethods = cloneStrings(ep.RADIUS.AllowedAuthenticationMethods)
		rad.AcceptStatusTypes = cloneStrings(ep.RADIUS.AcceptStatusTypes)
		out.RADIUS = &rad
	}
	return out
}

func cloneDocument(d *config.Document) *config.Document {
	if d == nil {
		return nil
	}
	out := *d
	out.Metadata.Labels = cloneLabels(d.Metadata.Labels)
	out.Listeners.HTTP.TrustedProxyCIDRs = cloneStrings(d.Listeners.HTTP.TrustedProxyCIDRs)
	out.API.MCP.AllowedOrigins = cloneStrings(d.API.MCP.AllowedOrigins)
	if d.API.BootstrapTokens != nil {
		out.API.BootstrapTokens = make([]config.BootstrapToken, len(d.API.BootstrapTokens))
		for i, tok := range d.API.BootstrapTokens {
			out.API.BootstrapTokens[i] = tok
			out.API.BootstrapTokens[i].Scopes = cloneStrings(tok.Scopes)
			out.API.BootstrapTokens[i].ExpiresAt = cloneTimePtr(tok.ExpiresAt)
			out.API.BootstrapTokens[i].Token = cloneSecretRef(tok.Token)
		}
	}
	out.Clients = make([]config.Client, len(d.Clients))
	for i := range d.Clients {
		out.Clients[i] = cloneClient(d.Clients[i])
	}
	out.Groups = make([]config.Group, len(d.Groups))
	for i := range d.Groups {
		out.Groups[i] = cloneGroup(d.Groups[i])
	}
	out.Users = make([]config.User, len(d.Users))
	for i := range d.Users {
		out.Users[i] = cloneUser(d.Users[i])
	}
	out.FallbackRules = cloneRuleSet(d.FallbackRules)
	out.FallbackRADIUSPolicyID = d.FallbackRADIUSPolicyID
	if d.RADIUSPolicies != nil {
		out.RADIUSPolicies = make([]config.RADIUSPolicy, len(d.RADIUSPolicies))
		for i, p := range d.RADIUSPolicies {
			out.RADIUSPolicies[i] = cloneRADIUSPolicy(p)
		}
	}
	if d.RADIUSReplyProfiles != nil {
		out.RADIUSReplyProfiles = make([]config.RADIUSReplyProfile, len(d.RADIUSReplyProfiles))
		for i, p := range d.RADIUSReplyProfiles {
			out.RADIUSReplyProfiles[i] = cloneRADIUSReplyProfile(p)
		}
	}
	if d.RADIUSDictionaries != nil {
		out.RADIUSDictionaries = make([]config.RADIUSDictionary, len(d.RADIUSDictionaries))
		copy(out.RADIUSDictionaries, d.RADIUSDictionaries)
	}
	if d.Listeners.SecureTACACS.TLS.Identities.Profiles != nil {
		out.Listeners.SecureTACACS.TLS.Identities.Profiles = make([]config.TLSProfile, len(d.Listeners.SecureTACACS.TLS.Identities.Profiles))
		for i, p := range d.Listeners.SecureTACACS.TLS.Identities.Profiles {
			out.Listeners.SecureTACACS.TLS.Identities.Profiles[i] = p
			out.Listeners.SecureTACACS.TLS.Identities.Profiles[i].ServerNames = cloneStrings(p.ServerNames)
			out.Listeners.SecureTACACS.TLS.Identities.Profiles[i].PrivateKey = cloneSecretRef(p.PrivateKey)
		}
	}
	return &out
}

func cloneMeta(m domain.ObjectMeta) domain.ObjectMeta {
	out := m
	out.Labels = cloneLabels(m.Labels)
	return out
}

func cloneRADIUSPolicy(p config.RADIUSPolicy) config.RADIUSPolicy {
	out := p
	if p.Rules != nil {
		out.Rules = make([]config.RADIUSRule, len(p.Rules))
		for i, r := range p.Rules {
			out.Rules[i] = r
			out.Rules[i].ReplyProfiles = cloneStrings(r.ReplyProfiles)
			out.Rules[i].Match.GroupsAny = cloneStrings(r.Match.GroupsAny)
			if r.Match.Method != nil {
				m := *r.Match.Method
				out.Rules[i].Match.Method = &m
			}
			if r.Match.Attributes != nil {
				out.Rules[i].Match.Attributes = make([]config.RADIUSAttrMatch, len(r.Match.Attributes))
				copy(out.Rules[i].Match.Attributes, r.Match.Attributes)
			}
		}
	}
	return out
}

func cloneRADIUSReplyProfile(p config.RADIUSReplyProfile) config.RADIUSReplyProfile {
	out := p
	if p.Attributes != nil {
		out.Attributes = make([]config.RADIUSReplyAttr, len(p.Attributes))
		copy(out.Attributes, p.Attributes)
	}
	return out
}

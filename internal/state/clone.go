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

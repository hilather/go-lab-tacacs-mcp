package config

import (
	"net"
	"regexp"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// ValidScope reports whether s is a known administrative scope.
func ValidScope(s string) bool {
	_, ok := knownScopes[s]
	return ok
}

// Scopes returns the administrative scope names in stable order.
// Matching is exact: state:write does not imply tokens:manage, runtime:reset,
// or config:reload.
func Scopes() []string {
	out := make([]string, len(scopeOrder))
	copy(out, scopeOrder)
	return out
}

// Known admin scopes. Tokens may list only these values.
var knownScopes = map[string]struct{}{
	"state:read":       {},
	"state:write":      {},
	"config:reload":    {},
	"config:export":    {},
	"policy:test":      {},
	"events:read":      {},
	"events:sensitive": {},
	"tokens:manage":    {},
	"runtime:reset":    {},
}

var scopeOrder = []string{
	"state:read",
	"state:write",
	"config:reload",
	"config:export",
	"policy:test",
	"events:read",
	"events:sensitive",
	"tokens:manage",
	"runtime:reset",
}

// Validate checks cross-object references, limits, command patterns, credential
// presence for enabled transports, and client-match uniqueness. It does not
// read secret files.
func Validate(doc *Document) error {
	if doc == nil {
		return domain.NewError(domain.CodeInvalidArgument, "document is required")
	}
	if err := validateLimits(doc); err != nil {
		return err
	}
	if err := validateListeners(doc); err != nil {
		return err
	}
	if err := validateBootstrapTokens(doc.API.BootstrapTokens); err != nil {
		return err
	}
	groups := make(map[string]struct{}, len(doc.Groups))
	for i, g := range doc.Groups {
		if _, ok := groups[g.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate group id").WithPath(indexPath("groups", i) + ".id")
		}
		groups[g.ID] = struct{}{}
		if g.DefaultCommandAction != "" && g.DefaultCommandAction != domain.DecisionDeny {
			return domain.NewError(domain.CodeInvalidArgument, "default_command_action must be deny").WithPath(indexPath("groups", i) + ".default_command_action")
		}
		if err := validateRuleSet(g.Services, g.CommandRules, indexPath("groups", i)); err != nil {
			return err
		}
	}
	clients := make(map[string]struct{}, len(doc.Clients))
	for i, c := range doc.Clients {
		if _, ok := clients[c.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate client id").WithPath(indexPath("clients", i) + ".id")
		}
		clients[c.ID] = struct{}{}
		if err := validateClient(c, groups, indexPath("clients", i)); err != nil {
			return err
		}
	}
	users := make(map[string]struct{}, len(doc.Users))
	for i, u := range doc.Users {
		if _, ok := users[u.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate user id").WithPath(indexPath("users", i) + ".id")
		}
		users[u.ID] = struct{}{}
		if err := validateUser(u, groups, clients, indexPath("users", i)); err != nil {
			return err
		}
	}
	if err := validateRuleSet(doc.FallbackRules.Services, doc.FallbackRules.CommandRules, "fallback_rules"); err != nil {
		return err
	}
	if _, err := CompileClientIndex(doc.Clients); err != nil {
		return err
	}
	return nil
}

func validateLimits(doc *Document) error {
	nUsers := len(doc.Users)
	nGroups := len(doc.Groups)
	nClients := len(doc.Clients)
	nTokens := len(doc.API.BootstrapTokens)
	if cap := doc.Runtime.MaxObjects.Users; cap > 0 && nUsers > cap {
		return domain.NewError(domain.CodeObjectLimitExceeded, "user count exceeds configured maximum").WithPath("users")
	}
	if cap := doc.Runtime.MaxObjects.Groups; cap > 0 && nGroups > cap {
		return domain.NewError(domain.CodeObjectLimitExceeded, "group count exceeds configured maximum").WithPath("groups")
	}
	if cap := doc.Runtime.MaxObjects.Clients; cap > 0 && nClients > cap {
		return domain.NewError(domain.CodeObjectLimitExceeded, "client count exceeds configured maximum").WithPath("clients")
	}
	if cap := doc.Runtime.MaxObjects.APITokens; cap > 0 && nTokens > cap {
		return domain.NewError(domain.CodeObjectLimitExceeded, "token count exceeds configured maximum").WithPath("api.bootstrap_tokens")
	}
	return nil
}

func validateListeners(doc *Document) error {
	legacy := doc.Listeners.LegacyTACACS
	secure := doc.Listeners.SecureTACACS
	if err := validateBind(legacy.Bind, "listeners.legacy_tacacs.bind"); err != nil {
		return err
	}
	if err := validateBind(secure.Bind, "listeners.secure_tacacs.bind"); err != nil {
		return err
	}
	if err := validateBind(doc.Listeners.HTTP.Bind, "listeners.http.bind"); err != nil {
		return err
	}
	if legacy.Enabled && secure.Enabled && legacy.Bind == secure.Bind {
		return domain.NewError(domain.CodeInvalidArgument, "legacy and secure TACACS listeners must use distinct binds").WithPath("listeners")
	}
	if !secure.Enabled {
		return nil
	}
	if len(secure.TLS.Identities.Profiles) == 0 {
		return domain.NewError(domain.CodeInvalidArgument, "secure TACACS requires at least one TLS identity profile").WithPath("listeners.secure_tacacs.tls.identities.profiles")
	}
	if secure.TLS.Identities.DefaultID != "" {
		found := false
		for _, p := range secure.TLS.Identities.Profiles {
			if p.ID == secure.TLS.Identities.DefaultID {
				found = true
				break
			}
		}
		if !found {
			return domain.NewError(domain.CodeInvalidArgument, "default TLS identity is not defined").WithPath("listeners.secure_tacacs.tls.identities.default_id")
		}
	}
	for i, p := range secure.TLS.Identities.Profiles {
		path := indexPath("listeners.secure_tacacs.tls.identities.profiles", i)
		if p.CertificateChain.File == "" {
			return domain.NewError(domain.CodeInvalidArgument, "certificate chain file is required").WithPath(path + ".certificate_chain")
		}
		if !p.PrivateKey.Set() {
			return domain.NewError(domain.CodeAuthMethodCredentialMissing, "TLS private key is required").WithPath(path + ".private_key")
		}
	}
	if secure.TLS.ClientCABundle.File == "" {
		return domain.NewError(domain.CodeInvalidArgument, "client CA bundle is required").WithPath("listeners.secure_tacacs.tls.client_ca_bundle")
	}
	if secure.TLS.Revocation.Mode == "configured_crl" && secure.TLS.Revocation.CRLBundle.File == "" {
		return domain.NewError(domain.CodeInvalidArgument, "CRL bundle is required when revocation.mode is configured_crl").WithPath("listeners.secure_tacacs.tls.revocation.crl_bundle")
	}
	return nil
}

func validateBind(bind, path string) error {
	if strings.TrimSpace(bind) == "" {
		return domain.NewError(domain.CodeInvalidArgument, "bind address is required").WithPath(path)
	}
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return domain.NewError(domain.CodeInvalidArgument, "bind address must be host:port").WithPath(path)
	}
	if port == "" {
		return domain.NewError(domain.CodeInvalidArgument, "bind address must be host:port").WithPath(path)
	}
	if host != "" && net.ParseIP(host) == nil && host != "*" {
		// hostnames are allowed; only reject obviously empty port cases above
		_ = host
	}
	return nil
}

func validateBootstrapTokens(tokens []BootstrapToken) error {
	seen := map[string]struct{}{}
	for i, tok := range tokens {
		path := indexPath("api.bootstrap_tokens", i)
		if tok.ID == "" {
			return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(path + ".id")
		}
		if _, ok := seen[tok.ID]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate token id").WithPath(path + ".id")
		}
		seen[tok.ID] = struct{}{}
		if !tok.Token.Set() {
			return domain.NewError(domain.CodeAuthMethodCredentialMissing, "bootstrap token secret is required").WithPath(path + ".token")
		}
		if len(tok.Scopes) == 0 {
			return domain.NewError(domain.CodeInvalidArgument, "at least one scope is required").WithPath(path + ".scopes")
		}
		for j, s := range tok.Scopes {
			if _, ok := knownScopes[s]; !ok {
				return domain.NewError(domain.CodeInvalidArgument, "unknown scope").WithPath(indexPath(path+".scopes", j))
			}
		}
	}
	return nil
}

func validateClient(c Client, groups map[string]struct{}, path string) error {
	if len(c.Match.Transports) == 0 {
		return domain.NewError(domain.CodeInvalidArgument, "at least one transport is required").WithPath(path + ".match.transports")
	}
	if hasTransport(c.Match.Transports, domain.TransportLegacy) && !c.Legacy.SharedSecret.Set() {
		return domain.NewError(domain.CodeAuthMethodCredentialMissing, "legacy transport requires a shared secret").WithPath(path + ".legacy.shared_secret")
	}
	for i, s := range c.Match.Certificate.IPSANs {
		if net.ParseIP(s) == nil {
			return domain.NewError(domain.CodeInvalidArgument, "invalid IP address").WithPath(indexPath(path+".match.certificate.ip_sans", i))
		}
	}
	for i, id := range c.Authorization.DefaultGroupIDs {
		if _, ok := groups[id]; !ok {
			return domain.NewError(domain.CodeGroupNotFound, "default group does not exist").WithPath(indexPath(path+".authorization.default_group_ids", i))
		}
	}
	return nil
}

func validateUser(u User, groups, clients map[string]struct{}, path string) error {
	for i, id := range u.GroupIDs {
		if _, ok := groups[id]; !ok {
			return domain.NewError(domain.CodeGroupNotFound, "group does not exist").WithPath(indexPath(path+".group_ids", i))
		}
	}
	for i, id := range u.Restrictions.ClientIDs {
		if _, ok := clients[id]; !ok {
			return domain.NewError(domain.CodeInvalidArgument, "restricted client does not exist").WithPath(indexPath(path+".restrictions.client_ids", i))
		}
	}
	if u.Restrictions.ValidAfter != nil && u.Restrictions.ValidBefore != nil && u.Restrictions.ValidAfter.After(*u.Restrictions.ValidBefore) {
		return domain.NewError(domain.CodeInvalidArgument, "valid_after must be before valid_before").WithPath(path + ".restrictions")
	}
	return validateRuleSet(u.Rules.Services, u.Rules.CommandRules, path+".rules")
}

func validateRuleSet(services []ServiceRule, commands []CommandRule, path string) error {
	prio := map[int]string{}
	for i, r := range commands {
		p := indexPath(path+".command_rules", i)
		if prev, ok := prio[r.Priority]; ok {
			return domain.NewError(domain.CodeInvalidArgument, "duplicate command rule priority "+itoa(r.Priority)+" (also "+prev+")").WithPath(p + ".priority")
		}
		prio[r.Priority] = r.ID
		if err := validateStringMatch(r.Command, p+".command"); err != nil {
			return err
		}
		if err := validateStringMatch(r.Arguments, p+".arguments"); err != nil {
			return err
		}
	}
	return nil
}

func validateStringMatch(m StringMatch, path string) error {
	if m.Pattern == "" {
		return nil
	}
	if _, err := regexp.Compile(m.Pattern); err != nil {
		return domain.NewError(domain.CodeRegexInvalid, "invalid regular expression").WithPath(path + ".pattern")
	}
	return nil
}

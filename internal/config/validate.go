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
// read secret files. Listener error paths follow Document.SchemaVersion.
func Validate(doc *Document) error {
	if doc == nil {
		return domain.NewError(domain.CodeInvalidArgument, "document is required")
	}
	schema := doc.SchemaVersion
	if schema == 0 {
		schema = SchemaVersionV1
	}
	return validateDocument(doc, schema)
}

// ValidateV2 is Validate using v2 listener paths. Callers that already know
// the source is v2 may use it directly.
func ValidateV2(doc *Document) error {
	if doc == nil {
		return domain.NewError(domain.CodeInvalidArgument, "document is required")
	}
	return validateDocument(doc, SchemaVersionV2)
}

func validateDocument(doc *Document, schema int) error {
	if err := validateLimits(doc); err != nil {
		return err
	}
	if err := validateListeners(doc, pathsForSchema(schema)); err != nil {
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
		// Flatten-first TACACS overlay patches do not rebuild endpoints.
		// Re-synthesize so projection stays aligned; RADIUS endpoints are canonical.
		if !hasRADIUSEndpoint(c) {
			doc.Clients[i].Endpoints = synthesizeTACACSEndpoints(c)
			c = doc.Clients[i]
		}
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
	if err := validateRADIUSPolicyRefs(doc, groups); err != nil {
		return err
	}
	if err := validateRADIUSDictionaries(doc); err != nil {
		return err
	}
	if _, err := CompileClientIndex(doc.Clients); err != nil {
		return err
	}
	if _, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccess); err != nil {
		return err
	}
	if _, err := CompileRADIUSIndex(doc.Clients, domain.RoleAccounting); err != nil {
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

func pathsForSchema(schema int) listenerYAMLPaths {
	if schema == SchemaVersionV2 {
		return v2ListenerPaths
	}
	return v1ListenerPaths
}

func validateListeners(doc *Document, paths listenerYAMLPaths) error {
	legacy := doc.Listeners.LegacyTACACS
	secure := doc.Listeners.SecureTACACS
	if err := validateBind(legacy.Bind, paths.Legacy+".bind"); err != nil {
		return err
	}
	if err := validateBind(secure.Bind, paths.Secure+".bind"); err != nil {
		return err
	}
	if err := validateBind(doc.Listeners.HTTP.Bind, paths.HTTP+".bind"); err != nil {
		return err
	}
	if err := validateRADIUSListener(doc.Listeners.RADIUSAccess, "listeners.radius.access", false); err != nil {
		return err
	}
	if err := validateRADIUSListener(doc.Listeners.RADIUSAccounting, "listeners.radius.accounting", true); err != nil {
		return err
	}
	if doc.Listeners.RADIUSAccess.Enabled && doc.Listeners.RADIUSAccounting.Enabled &&
		doc.Listeners.RADIUSAccess.Bind == doc.Listeners.RADIUSAccounting.Bind {
		return domain.NewError(domain.CodeInvalidArgument, "RADIUS access and accounting listeners must use distinct binds").WithPath("listeners.radius")
	}
	if legacy.Enabled && secure.Enabled && legacy.Bind == secure.Bind {
		return domain.NewError(domain.CodeInvalidArgument, "legacy and secure TACACS listeners must use distinct binds").WithPath("listeners")
	}
	if !secure.Enabled {
		return nil
	}
	tlsPath := paths.Secure + ".tls"
	if len(secure.TLS.Identities.Profiles) == 0 {
		return domain.NewError(domain.CodeInvalidArgument, "secure TACACS requires at least one TLS identity profile").WithPath(tlsPath + ".identities.profiles")
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
			return domain.NewError(domain.CodeInvalidArgument, "default TLS identity is not defined").WithPath(tlsPath + ".identities.default_id")
		}
	}
	for i, p := range secure.TLS.Identities.Profiles {
		path := indexPath(tlsPath+".identities.profiles", i)
		if p.CertificateChain.File == "" {
			return domain.NewError(domain.CodeInvalidArgument, "certificate chain file is required").WithPath(path + ".certificate_chain")
		}
		if !p.PrivateKey.Set() {
			return domain.NewError(domain.CodeAuthMethodCredentialMissing, "TLS private key is required").WithPath(path + ".private_key")
		}
	}
	if secure.TLS.ClientCABundle.File == "" {
		return domain.NewError(domain.CodeInvalidArgument, "client CA bundle is required").WithPath(tlsPath + ".client_ca_bundle")
	}
	if secure.TLS.Revocation.Mode == "configured_crl" && secure.TLS.Revocation.CRLBundle.File == "" {
		return domain.NewError(domain.CodeInvalidArgument, "CRL bundle is required when revocation.mode is configured_crl").WithPath(tlsPath + ".revocation.crl_bundle")
	}
	if !secure.TLS.RejectEarlyData {
		return domain.NewError(domain.CodeInvalidArgument, "reject_early_data cannot be disabled").WithPath(tlsPath + ".reject_early_data")
	}
	if !secure.TLS.SessionResumption.RecheckClientRevocation {
		return domain.NewError(domain.CodeInvalidArgument, "recheck_client_revocation cannot be disabled (ADR-0005)").
			WithPath(tlsPath + ".session_resumption.recheck_client_revocation")
	}
	if secure.TLS.SessionResumption.Enabled {
		life := secure.TLS.SessionResumption.TicketLifetime
		if life != 0 && life != TLSTicketLifetimeEnforced {
			return domain.NewError(domain.CodeInvalidArgument, "ticket_lifetime must be 0 (disabled) or 168h (Go crypto/tls cap; ADR-0005)").
				WithPath(tlsPath+".session_resumption.ticket_lifetime").
				WithDetail("enforced", TLSTicketLifetimeEnforced.String())
		}
	}
	for i, p := range secure.TLS.Identities.Profiles {
		path := indexPath(tlsPath+".identities.profiles", i)
		for j, name := range p.ServerNames {
			if err := ValidateWildcardServerName(name); err != nil {
				return domain.NewError(domain.CodeInvalidArgument, err.Error()).WithPath(indexPath(path+".server_names", j))
			}
		}
	}
	return nil
}

func validateRADIUSListener(l RADIUSListener, path string, accounting bool) error {
	if err := validateBind(l.Bind, path+".bind"); err != nil {
		return err
	}
	if l.Transport != "" && l.Transport != RADIUSTransportUDP {
		return domain.NewError(domain.CodeInvalidArgument, "transport must be udp").WithPath(path + ".transport")
	}
	if l.MaxPacketBytes < RADIUSMinPacketBytes || l.MaxPacketBytes > RADIUSMaxPacketBytes {
		return domain.NewError(domain.CodeInvalidArgument, "max_packet_bytes must be between 20 and 4096").WithPath(path + ".max_packet_bytes")
	}
	if l.QueueCapacity <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "queue_capacity must be > 0").WithPath(path + ".queue_capacity")
	}
	if l.Workers <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "workers must be > 0").WithPath(path + ".workers")
	}
	if l.WorkerDeadline <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "worker_deadline must be > 0").WithPath(path + ".worker_deadline")
	}
	if l.RetransmissionCacheEntries <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "retransmission_cache_entries must be > 0").WithPath(path + ".retransmission_cache_entries")
	}
	if l.RetransmissionCacheBytes <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "retransmission_cache_bytes must be > 0").WithPath(path + ".retransmission_cache_bytes")
	}
	if accounting {
		if l.RetransmissionTTL <= 0 || l.RetransmissionTTL > RADIUSAccountingRetransmissionTTLMax {
			return domain.NewError(domain.CodeInvalidArgument, "retransmission_ttl must be between 1ns and 300s").WithPath(path + ".retransmission_ttl")
		}
		if l.JournalEntries <= 0 {
			return domain.NewError(domain.CodeInvalidArgument, "journal_entries must be > 0").WithPath(path + ".journal_entries")
		}
		if l.JournalBytes <= 0 {
			return domain.NewError(domain.CodeInvalidArgument, "journal_bytes must be > 0").WithPath(path + ".journal_bytes")
		}
		if l.AmbiguousAccountingPerMinute < 0 {
			return domain.NewError(domain.CodeInvalidArgument, "ambiguous_accounting_per_minute must be >= 0").WithPath(path + ".ambiguous_accounting_per_minute")
		}
	} else {
		if l.RetransmissionTTL < RADIUSAccessRetransmissionTTLMin || l.RetransmissionTTL > RADIUSAccessRetransmissionTTLMax {
			return domain.NewError(domain.CodeInvalidArgument, "retransmission_ttl must be between 5s and 30s").WithPath(path + ".retransmission_ttl")
		}
		switch l.MessageAuthenticator {
		case "", RADIUSMessageAuthenticatorRequired, RADIUSMessageAuthenticatorAllowMissing:
		default:
			return domain.NewError(domain.CodeInvalidArgument, "message_authenticator must be required or allow_missing").WithPath(path + ".message_authenticator")
		}
		if l.ChallengeTTL < RADIUSChallengeTTLMin || l.ChallengeTTL > RADIUSChallengeTTLMax {
			return domain.NewError(domain.CodeInvalidArgument, "challenge_ttl must be between 5s and 60s").WithPath(path + ".challenge_ttl")
		}
		if l.ChallengeEntries < RADIUSChallengeEntriesMin || l.ChallengeEntries > RADIUSChallengeEntriesMax {
			return domain.NewError(domain.CodeInvalidArgument, "challenge_entries must be between 16 and 65536").WithPath(path + ".challenge_entries")
		}
		if l.ChallengeBytes < RADIUSChallengeBytesMin || l.ChallengeBytes > RADIUSChallengeBytesMax {
			return domain.NewError(domain.CodeInvalidArgument, "challenge_bytes must be between 64KiB and 8MiB").WithPath(path + ".challenge_bytes")
		}
	}
	if l.PerSourceRate <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "per_source_rate must be > 0").WithPath(path + ".per_source_rate")
	}
	if l.PerSourceBurst <= 0 {
		return domain.NewError(domain.CodeInvalidArgument, "per_source_burst must be > 0").WithPath(path + ".per_source_burst")
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
	if hasRADIUSEndpoint(c) {
		if err := checkClientProjection(c, path); err != nil {
			return err
		}
	}
	hasTACACS := len(c.Match.Transports) > 0
	rad := radiusEndpoint(c)
	if !hasTACACS && rad == nil {
		return domain.NewError(domain.CodeInvalidArgument, "at least one transport is required").WithPath(path + ".match.transports")
	}
	if hasTransport(c.Match.Transports, domain.TransportLegacy) && !c.Legacy.SharedSecret.Set() {
		return domain.NewError(domain.CodeAuthMethodCredentialMissing, "legacy transport requires a shared secret").WithPath(path + ".legacy.shared_secret")
	}
	if c.Match.Mode == domain.MatchCertificateOnly && !hasTACACSTLSEndpoint(c) {
		return domain.NewError(domain.CodeInvalidArgument, "certificate_only requires a TACACS TLS endpoint").WithPath(path + ".match.mode")
	}
	if rad != nil {
		if !rad.RADIUS.SharedSecret.Set() {
			return domain.NewError(domain.CodeRADIUSSecretMissing, "RADIUS endpoint requires a shared secret").WithPath(path + ".endpoints")
		}
		if len(c.Match.SourceCIDRs) == 0 {
			return domain.NewError(domain.CodeInvalidArgument, "RADIUS clients require match.source_cidrs").WithPath(path + ".match.source_cidrs")
		}
		if c.Match.Mode == domain.MatchCertificateOnly && !hasTACACS {
			return domain.NewError(domain.CodeInvalidArgument, "RADIUS-only clients cannot use certificate_only").WithPath(path + ".match.mode")
		}
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
	if u.MustChangeLogin && !u.Credentials.Login.Verifier.Set() {
		return domain.NewError(domain.CodeInvalidArgument, "must_change_login requires a login verifier").WithPath(path + ".must_change_login")
	}
	if u.MustChangeEnable && !u.Credentials.Enable.Verifier.Set() {
		return domain.NewError(domain.CodeInvalidArgument, "must_change_enable requires an enable verifier").WithPath(path + ".must_change_enable")
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

package config

import (
	"net"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"golang.org/x/text/secure/precis"
)

func normalizeV1(raw *rawFileV1) (*Document, error) {
	doc, err := normalizeCommon(raw)
	if err != nil {
		return nil, err
	}
	migrateV1ToNormalized(doc)
	return doc, nil
}

// migrateV1ToNormalized fills v2-normalized fields that v1 syntax cannot
// express. The source file is never rewritten. SchemaVersion stays 1.
func migrateV1ToNormalized(doc *Document) {
	if doc == nil {
		return
	}
	doc.SchemaVersion = SchemaVersionV1
	doc.Server.AdminOnly = false
	doc.Security.RADIUSSharedSecrets = doc.Security.LegacySharedSecrets
	if doc.Listeners.RADIUSAccess.MaxPacketBytes == 0 {
		doc.Listeners.RADIUSAccess = defaultRADIUSAccess()
	}
	if doc.Listeners.RADIUSAccounting.MaxPacketBytes == 0 {
		doc.Listeners.RADIUSAccounting = defaultRADIUSAccounting()
	}
	doc.Listeners.RADIUSAccess.Enabled = false
	doc.Listeners.RADIUSAccounting.Enabled = false
}

func normalizeCommon(raw *rawFile) (*Document, error) {
	doc := defaultDocument()
	doc.Metadata = Metadata{
		Name:        raw.Metadata.Name,
		Description: raw.Metadata.Description,
		Labels:      copyLabels(raw.Metadata.Labels),
	}

	if err := normalizeServer(&doc.Server, raw.Server); err != nil {
		return nil, err
	}
	if err := normalizeRuntime(&doc.Runtime, raw.Runtime); err != nil {
		return nil, err
	}
	if err := normalizeSecurity(&doc.Security, raw.Security); err != nil {
		return nil, err
	}
	if err := normalizeListeners(&doc.Listeners, raw.Listeners, v1ListenerPaths, doc.Security.AllowEnvironmentSecrets); err != nil {
		return nil, err
	}
	if err := normalizeAPI(&doc.API, raw.API, doc.Listeners.HTTP.TLS.Enabled, doc.Security.AllowEnvironmentSecrets); err != nil {
		return nil, err
	}
	if err := normalizeLimits(&doc.Limits, raw.Limits); err != nil {
		return nil, err
	}

	clients, err := normalizeClients(raw.Clients, doc.Security.AllowEnvironmentSecrets)
	if err != nil {
		return nil, err
	}
	doc.Clients = clients

	groups, err := normalizeGroups(raw.Groups)
	if err != nil {
		return nil, err
	}
	doc.Groups = groups

	users, err := normalizeUsers(raw.Users, doc.Security.AllowEnvironmentSecrets)
	if err != nil {
		return nil, err
	}
	doc.Users = users

	fb, err := normalizeRuleSet(raw.FallbackRules, "fallback_rules")
	if err != nil {
		return nil, err
	}
	doc.FallbackRules = fb

	if err := normalizeEvents(&doc.Events, raw.Events); err != nil {
		return nil, err
	}
	if err := normalizeObservability(&doc.Observability, raw.Observability); err != nil {
		return nil, err
	}
	doc.SchemaVersion = SchemaVersionV1
	return &doc, nil
}

func normalizeServer(dst *Server, raw rawServer) error {
	if raw.InstanceID != "" {
		dst.InstanceID = raw.InstanceID
	}
	d, err := parseDurationOr(raw.ShutdownGrace, "server.shutdown_grace", dst.ShutdownGrace)
	if err != nil {
		return err
	}
	dst.ShutdownGrace = d
	if raw.StartupFailureMode != "" {
		if raw.StartupFailureMode != "fail_closed" {
			return yamlErrorAt("server.startup_failure_mode", "startup_failure_mode must be fail_closed")
		}
		dst.StartupFailureMode = raw.StartupFailureMode
	}
	if raw.LogLevel != "" {
		dst.LogLevel = raw.LogLevel
	}
	return nil
}

func normalizeRuntime(dst *Runtime, raw rawRuntime) error {
	if raw.Persistence != "" {
		if raw.Persistence != "memory" {
			return yamlErrorAt("runtime.persistence", "persistence must be memory")
		}
		dst.Persistence = raw.Persistence
	}
	dst.AllowShadowing = boolOr(raw.AllowShadowing, dst.AllowShadowing)
	if raw.DeleteBaselineBehavior != "" {
		if raw.DeleteBaselineBehavior != "tombstone" {
			return yamlErrorAt("runtime.delete_baseline_behavior", "delete_baseline_behavior must be tombstone")
		}
		dst.DeleteBaselineBehavior = raw.DeleteBaselineBehavior
	}
	if raw.ReloadOverlayBehavior != "" {
		switch raw.ReloadOverlayBehavior {
		case "rebase", "reset":
			dst.ReloadOverlayBehavior = raw.ReloadOverlayBehavior
		default:
			return yamlErrorAt("runtime.reload_overlay_behavior", "reload_overlay_behavior must be rebase or reset")
		}
	}
	if raw.ResetRequiresScope != "" {
		dst.ResetRequiresScope = raw.ResetRequiresScope
	}
	dst.MaxObjects.Users = intOr(raw.MaxObjects.Users, dst.MaxObjects.Users)
	dst.MaxObjects.Groups = intOr(raw.MaxObjects.Groups, dst.MaxObjects.Groups)
	dst.MaxObjects.Clients = intOr(raw.MaxObjects.Clients, dst.MaxObjects.Clients)
	dst.MaxObjects.APITokens = intOr(raw.MaxObjects.APITokens, dst.MaxObjects.APITokens)
	return nil
}

func normalizeSecurity(dst *Security, raw rawSecurity) error {
	dst.AllowEnvironmentSecrets = boolOr(raw.AllowEnvironmentSecrets, dst.AllowEnvironmentSecrets)
	dst.StrictSecretFiles = boolOr(raw.StrictSecretFiles, dst.StrictSecretFiles)
	return applySharedSecretPolicy(&dst.LegacySharedSecrets, raw.LegacySharedSecrets, "security.legacy_shared_secrets")
}

func applySharedSecretPolicy(p *SharedSecretPolicy, raw rawSharedSecretPolicy, path string) error {
	p.MinimumLengthCharacters = intOr(raw.MinimumLengthCharacters, p.MinimumLengthCharacters)
	p.MinimumCharacterClasses = intOr(raw.MinimumCharacterClasses, p.MinimumCharacterClasses)
	if p.MinimumCharacterClasses < 0 || p.MinimumCharacterClasses > 4 {
		return yamlErrorAt(path+".minimum_character_classes", "minimum_character_classes must be 0-4")
	}
	if p.MinimumLengthCharacters < 0 {
		return yamlErrorAt(path+".minimum_length_characters", "minimum_length_characters must be >= 0")
	}
	p.RejectKnownWeakValues = boolOr(raw.RejectKnownWeakValues, p.RejectKnownWeakValues)
	p.WarnOnReuse = boolOr(raw.WarnOnReuse, p.WarnOnReuse)
	d, err := parseDurationOr(raw.DefaultRotationInterval, path+".default_rotation_interval", p.DefaultRotationInterval)
	if err != nil {
		return err
	}
	p.DefaultRotationInterval = d
	w, err := parseDurationOr(raw.RotationWarningBefore, path+".rotation_warning_before", p.RotationWarningBefore)
	if err != nil {
		return err
	}
	p.RotationWarningBefore = w
	return nil
}

type listenerYAMLPaths struct {
	Legacy string
	Secure string
	HTTP   string
}

var v1ListenerPaths = listenerYAMLPaths{
	Legacy: "listeners.legacy_tacacs",
	Secure: "listeners.secure_tacacs",
	HTTP:   "listeners.http",
}

var v2ListenerPaths = listenerYAMLPaths{
	Legacy: "listeners.tacacs.legacy",
	Secure: "listeners.tacacs.tls",
	HTTP:   "listeners.http",
}

func normalizeListeners(dst *Listeners, raw rawListeners, paths listenerYAMLPaths, allowEnv bool) error {
	if err := normalizeTACACS(&dst.LegacyTACACS, raw.LegacyTACACS, paths.Legacy); err != nil {
		return err
	}
	if err := normalizeTACACS(&dst.SecureTACACS.TACACSListener, raw.SecureTACACS.rawTACACSListener, paths.Secure); err != nil {
		return err
	}
	if err := normalizeSecureTLS(&dst.SecureTACACS.TLS, raw.SecureTACACS.TLS, paths.Secure+".tls", allowEnv); err != nil {
		return err
	}
	return normalizeHTTP(&dst.HTTP, raw.HTTP)
}

func normalizeTACACS(dst *TACACSListener, raw rawTACACSListener, path string) error {
	dst.Enabled = boolOr(raw.Enabled, dst.Enabled)
	if raw.Bind != "" {
		dst.Bind = raw.Bind
	}
	dst.AdvertisedPort = intOr(raw.AdvertisedPort, dst.AdvertisedPort)
	var err error
	if dst.ReadTimeout, err = parseDurationOr(raw.ReadTimeout, path+".read_timeout", dst.ReadTimeout); err != nil {
		return err
	}
	if dst.WriteTimeout, err = parseDurationOr(raw.WriteTimeout, path+".write_timeout", dst.WriteTimeout); err != nil {
		return err
	}
	if dst.IdleTimeout, err = parseDurationOr(raw.IdleTimeout, path+".idle_timeout", dst.IdleTimeout); err != nil {
		return err
	}
	if dst.HandshakeTimeout, err = parseDurationOr(raw.HandshakeTimeout, path+".handshake_timeout", dst.HandshakeTimeout); err != nil {
		return err
	}
	dst.MaxConnections = intOr(raw.MaxConnections, dst.MaxConnections)
	dst.MaxSessionsPerConnection = intOr(raw.MaxSessionsPerConnection, dst.MaxSessionsPerConnection)
	dst.MaxPacketBodyBytes = intOr(raw.MaxPacketBodyBytes, dst.MaxPacketBodyBytes)
	dst.SingleConnect.Enabled = boolOr(raw.SingleConnect.Enabled, dst.SingleConnect.Enabled)
	if dst.SingleConnect.MaxLifetime, err = parseDurationOr(raw.SingleConnect.MaxLifetime, path+".single_connect.max_lifetime", dst.SingleConnect.MaxLifetime); err != nil {
		return err
	}
	if dst.SingleConnect.IdleTimeout, err = parseDurationOr(raw.SingleConnect.IdleTimeout, path+".single_connect.idle_timeout", dst.SingleConnect.IdleTimeout); err != nil {
		return err
	}
	return nil
}

func normalizeSecureTLS(dst *SecureTLS, raw rawSecureTLS, path string, allowEnv bool) error {
	if raw.MinimumVersion != "" {
		if raw.MinimumVersion != "TLS1.3" {
			return domain.NewError(domain.CodeTLSVersionUnsupported, "secure TACACS minimum_version must be TLS1.3").WithPath(path + ".minimum_version")
		}
		dst.MinimumVersion = raw.MinimumVersion
	}
	if raw.ClientAuthentication != "" {
		if raw.ClientAuthentication != "require_and_verify_certificate" {
			return yamlErrorAt(path+".client_authentication", "client_authentication must be require_and_verify_certificate")
		}
		dst.ClientAuthentication = raw.ClientAuthentication
	}
	dst.Identities.DefaultID = raw.Identities.DefaultID
	dst.Identities.RequireSNI = boolOr(raw.Identities.RequireSNI, dst.Identities.RequireSNI)
	profiles := make([]TLSProfile, 0, len(raw.Identities.Profiles))
	seen := map[string]struct{}{}
	for i, p := range raw.Identities.Profiles {
		ppath := indexPath(path+".identities.profiles", i)
		if p.ID == "" {
			return yamlErrorAt(ppath+".id", "id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return yamlErrorAt(ppath+".id", "duplicate TLS identity id")
		}
		seen[p.ID] = struct{}{}
		key, err := normalizeSecretRef(p.PrivateKey, credentials.PurposeTLSPrivateKey, ppath+".private_key", allowEnv)
		if err != nil {
			return err
		}
		profiles = append(profiles, TLSProfile{
			ID:               p.ID,
			ServerNames:      copyStrings(p.ServerNames),
			CertificateChain: normalizeFileRef(p.CertificateChain),
			PrivateKey:       key,
		})
	}
	dst.Identities.Profiles = profiles
	dst.ClientCABundle = normalizeFileRef(raw.ClientCABundle)
	if raw.Revocation.Mode != "" {
		if raw.Revocation.Mode != "configured_crl" {
			return yamlErrorAt(path+".revocation.mode", "revocation.mode must be configured_crl")
		}
		dst.Revocation.Mode = raw.Revocation.Mode
	}
	dst.Revocation.CRLBundle = normalizeFileRef(raw.Revocation.CRLBundle)
	dst.SessionResumption.Enabled = boolOr(raw.SessionResumption.Enabled, dst.SessionResumption.Enabled)
	d, err := parseDurationOr(raw.SessionResumption.TicketLifetime, path+".session_resumption.ticket_lifetime", dst.SessionResumption.TicketLifetime)
	if err != nil {
		return err
	}
	dst.SessionResumption.TicketLifetime = d
	dst.SessionResumption.RecheckClientRevocation = boolOr(raw.SessionResumption.RecheckClientRevocation, dst.SessionResumption.RecheckClientRevocation)
	dst.RejectEarlyData = boolOr(raw.RejectEarlyData, dst.RejectEarlyData)
	return nil
}

func normalizeHTTP(dst *HTTPListener, raw rawHTTPListener) error {
	dst.Enabled = boolOr(raw.Enabled, dst.Enabled)
	if raw.Bind != "" {
		dst.Bind = raw.Bind
	}
	var err error
	if dst.ReadHeaderTimeout, err = parseDurationOr(raw.ReadHeaderTimeout, "listeners.http.read_header_timeout", dst.ReadHeaderTimeout); err != nil {
		return err
	}
	if dst.ReadTimeout, err = parseDurationOr(raw.ReadTimeout, "listeners.http.read_timeout", dst.ReadTimeout); err != nil {
		return err
	}
	if dst.WriteTimeout, err = parseDurationOr(raw.WriteTimeout, "listeners.http.write_timeout", dst.WriteTimeout); err != nil {
		return err
	}
	if dst.IdleTimeout, err = parseDurationOr(raw.IdleTimeout, "listeners.http.idle_timeout", dst.IdleTimeout); err != nil {
		return err
	}
	dst.MaxRequestBodyBytes = int64Or(raw.MaxRequestBodyBytes, dst.MaxRequestBodyBytes)
	cidrs, err := normalizeCIDRs(raw.TrustedProxyCIDRs, "listeners.http.trusted_proxy_cidrs")
	if err != nil {
		return err
	}
	if raw.TrustedProxyCIDRs != nil {
		dst.TrustedProxyCIDRs = cidrs
	} else if dst.TrustedProxyCIDRs == nil {
		dst.TrustedProxyCIDRs = []string{}
	}
	dst.TLS.Enabled = boolOr(raw.TLS.Enabled, dst.TLS.Enabled)
	return nil
}

func normalizeAPI(dst *API, raw rawAPI, httpTLS bool, allowEnv bool) error {
	if raw.Mode != "" {
		if raw.Mode != "lab_static_bearer" {
			return yamlErrorAt("api.mode", "api.mode must be lab_static_bearer")
		}
		dst.Mode = raw.Mode
	}
	dst.UISession.Enabled = boolOr(raw.UISession.Enabled, dst.UISession.Enabled)
	var err error
	if dst.UISession.Lifetime, err = parseDurationOr(raw.UISession.Lifetime, "api.ui_session.lifetime", dst.UISession.Lifetime); err != nil {
		return err
	}
	if dst.UISession.IdleTimeout, err = parseDurationOr(raw.UISession.IdleTimeout, "api.ui_session.idle_timeout", dst.UISession.IdleTimeout); err != nil {
		return err
	}
	if raw.UISession.CookieSameSite != "" {
		switch strings.ToLower(raw.UISession.CookieSameSite) {
		case "strict", "lax", "none":
			dst.UISession.CookieSameSite = strings.ToLower(raw.UISession.CookieSameSite)
		default:
			return yamlErrorAt("api.ui_session.cookie_same_site", "cookie_same_site must be strict, lax, or none")
		}
	}
	dst.UISession.CookieSecure = boolOr(raw.UISession.CookieSecure, httpTLS)

	if raw.MCP.AllowedOrigins != nil {
		dst.MCP.AllowedOrigins = copyStrings(raw.MCP.AllowedOrigins)
	} else {
		dst.MCP.AllowedOrigins = []string{}
	}
	dst.MCP.RequireOrigin = boolOr(raw.MCP.RequireOrigin, false)
	dst.MCP.AllowLegacyClients = boolOr(raw.MCP.AllowLegacyClients, false)

	tokens := make([]BootstrapToken, 0, len(raw.BootstrapTokens))
	seen := map[string]struct{}{}
	for i, t := range raw.BootstrapTokens {
		path := indexPath("api.bootstrap_tokens", i)
		if t.ID == "" {
			return yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[t.ID]; ok {
			return yamlErrorAt(path+".id", "duplicate token id")
		}
		seen[t.ID] = struct{}{}
		ref, err := normalizeSecretRef(t.Token, credentials.PurposeAPIBearerToken, path+".token", allowEnv)
		if err != nil {
			return err
		}
		tokens = append(tokens, BootstrapToken{
			ID:        t.ID,
			Token:     ref,
			Scopes:    copyStrings(t.Scopes),
			ExpiresAt: cloneTime(t.ExpiresAt),
		})
	}
	dst.BootstrapTokens = tokens

	dst.RateLimits.Enabled = boolOr(raw.RateLimits.Enabled, dst.RateLimits.Enabled)
	dst.RateLimits.PerTokenRequestsPerSecond = floatOr(raw.RateLimits.PerTokenRequestsPerSecond, dst.RateLimits.PerTokenRequestsPerSecond)
	dst.RateLimits.PerTokenBurst = intOr(raw.RateLimits.PerTokenBurst, dst.RateLimits.PerTokenBurst)
	dst.RateLimits.UnauthenticatedRequestsPerSecond = floatOr(raw.RateLimits.UnauthenticatedRequestsPerSecond, dst.RateLimits.UnauthenticatedRequestsPerSecond)
	dst.RateLimits.UnauthenticatedBurst = intOr(raw.RateLimits.UnauthenticatedBurst, dst.RateLimits.UnauthenticatedBurst)
	return nil
}

func normalizeLimits(dst *Limits, raw rawLimits) error {
	dst.MaxUsernameBytes = intOr(raw.MaxUsernameBytes, dst.MaxUsernameBytes)
	dst.MaxPortBytes = intOr(raw.MaxPortBytes, dst.MaxPortBytes)
	dst.MaxRemoteAddressBytes = intOr(raw.MaxRemoteAddressBytes, dst.MaxRemoteAddressBytes)
	dst.MaxAuthenticationRounds = intOr(raw.MaxAuthenticationRounds, dst.MaxAuthenticationRounds)
	dst.MaxAuthorizationArguments = intOr(raw.MaxAuthorizationArguments, dst.MaxAuthorizationArguments)
	dst.MaxArgumentBytes = intOr(raw.MaxArgumentBytes, dst.MaxArgumentBytes)
	dst.MaxCommandBytes = intOr(raw.MaxCommandBytes, dst.MaxCommandBytes)
	dst.MaxPolicyTraceSteps = intOr(raw.MaxPolicyTraceSteps, dst.MaxPolicyTraceSteps)
	dst.MaxEventPayloadBytes = intOr(raw.MaxEventPayloadBytes, dst.MaxEventPayloadBytes)
	return nil
}

func normalizeClients(raw []rawClient, allowEnv bool) ([]Client, error) {
	out, err := normalizeClientsFlatten(raw, allowEnv)
	if err != nil {
		return nil, err
	}
	finalizeMissingEndpoints(out)
	return out, nil
}

func normalizeClientsFlatten(raw []rawClient, allowEnv bool) ([]Client, error) {
	out := make([]Client, 0, len(raw))
	seen := map[string]struct{}{}
	for i, c := range raw {
		path := indexPath("clients", i)
		if c.ID == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[c.ID]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate client id")
		}
		seen[c.ID] = struct{}{}
		match, err := normalizeClientMatch(c.Match, path+".match")
		if err != nil {
			return nil, err
		}
		sec, err := normalizeSecretRef(c.Legacy.SharedSecret, credentials.PurposeLegacySharedSecret, path+".legacy.shared_secret", allowEnv)
		if err != nil {
			return nil, err
		}
		rot, err := parseDuration(c.Legacy.SharedSecretLifecycle.RotationInterval, path+".legacy.shared_secret_lifecycle.rotation_interval")
		if err != nil {
			return nil, err
		}
		auth, err := normalizeClientAuth(c.Authentication, path+".authentication")
		if err != nil {
			return nil, err
		}
		acctEnabled := boolOr(c.Accounting.Enabled, true)
		out = append(out, Client{
			ID:          c.ID,
			DisplayName: c.DisplayName,
			Priority:    intOr(c.Priority, 0),
			Enabled:     boolOr(c.Enabled, true),
			Labels:      copyLabels(c.Labels),
			Match:       match,
			Legacy: ClientLegacy{
				SharedSecret: sec,
				SharedSecretLifecycle: SecretLifecycleMeta{
					LastRotatedAt:    cloneTime(c.Legacy.SharedSecretLifecycle.LastRotatedAt),
					RotationInterval: rot,
				},
			},
			Authentication: auth,
			Authorization:  ClientAuthz{DefaultGroupIDs: copyStrings(c.Authorization.DefaultGroupIDs)},
			Accounting: ClientAcct{
				Enabled:        acctEnabled,
				AcceptStart:    boolOr(c.Accounting.AcceptStart, acctEnabled),
				AcceptStop:     boolOr(c.Accounting.AcceptStop, acctEnabled),
				AcceptWatchdog: boolOr(c.Accounting.AcceptWatchdog, acctEnabled),
			},
		})
	}
	return out, nil
}

func normalizeClientMatch(raw rawClientMatch, path string) (ClientMatch, error) {
	mode := domain.MatchAddressAndCertificate
	if raw.Mode != "" {
		m, err := domain.ParseMatchMode(raw.Mode)
		if err != nil {
			return ClientMatch{}, yamlErrorAt(path+".mode", "match mode must be address_and_certificate or certificate_only")
		}
		mode = m
	}
	cidrs, err := normalizeCIDRs(raw.SourceCIDRs, path+".source_cidrs")
	if err != nil {
		return ClientMatch{}, err
	}
	transports := make([]domain.Transport, 0, len(raw.Transports))
	for i, s := range raw.Transports {
		tr, err := domain.ParseTransport(s)
		if err != nil {
			return ClientMatch{}, yamlErrorAt(indexPath(path+".transports", i), "transport must be legacy or tls")
		}
		transports = append(transports, tr)
	}
	ips := make([]string, 0, len(raw.Certificate.IPSANs))
	for i, s := range raw.Certificate.IPSANs {
		ip := net.ParseIP(s)
		if ip == nil {
			return ClientMatch{}, yamlErrorAt(indexPath(path+".certificate.ip_sans", i), "invalid IP address")
		}
		ips = append(ips, ip.String())
	}
	return ClientMatch{
		SourceCIDRs: cidrs,
		Transports:  transports,
		Mode:        mode,
		Certificate: CertMatch{
			DNSSANs: copyStrings(raw.Certificate.DNSSANs),
			IPSANs:  ips,
		},
	}, nil
}

func normalizeClientAuth(raw rawClientAuth, path string) (ClientAuth, error) {
	methods := make([]AuthMethod, 0, len(raw.AllowedMethods))
	for i, s := range raw.AllowedMethods {
		m, err := parseAuthMethod(s)
		if err != nil {
			return ClientAuth{}, yamlErrorAt(indexPath(path+".allowed_methods", i), "unknown authentication method")
		}
		methods = append(methods, m)
	}
	svc := domain.AuthenServiceNone
	if raw.DefaultService != "" {
		parsed, err := domain.ParseAuthenService(raw.DefaultService)
		if err != nil {
			return ClientAuth{}, yamlErrorAt(path+".default_service", "unknown authentication service")
		}
		svc = parsed
	}
	return ClientAuth{AllowedMethods: methods, DefaultService: svc}, nil
}

func parseAuthMethod(s string) (AuthMethod, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ascii":
		return AuthMethodASCII, nil
	case "pap":
		return AuthMethodPAP, nil
	case "chap":
		return AuthMethodCHAP, nil
	case "mschap", "mschapv1":
		return AuthMethodMSCHAPv1, nil
	case "mschapv2":
		return AuthMethodMSCHAPv2, nil
	case "enable":
		return AuthMethodEnable, nil
	case "ascii_chpass":
		return AuthMethodASCIIChpass, nil
	default:
		return "", yamlError("unknown authentication method")
	}
}

func normalizeGroups(raw []rawGroup) ([]Group, error) {
	out := make([]Group, 0, len(raw))
	seen := map[string]struct{}{}
	for i, g := range raw {
		path := indexPath("groups", i)
		if g.ID == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		if _, ok := seen[g.ID]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate group id")
		}
		seen[g.ID] = struct{}{}
		dca, err := normalizeDefaultCommandAction(g.DefaultCommandAction, path+".default_command_action")
		if err != nil {
			return nil, err
		}
		svcs, err := normalizeServiceRules(g.Services, path+".services")
		if err != nil {
			return nil, err
		}
		cmds, err := normalizeCommandRules(g.CommandRules, path+".command_rules")
		if err != nil {
			return nil, err
		}
		out = append(out, Group{
			ID:                   g.ID,
			DisplayName:          g.DisplayName,
			Priority:             intOr(g.Priority, 0),
			Enabled:              boolOr(g.Enabled, true),
			Labels:               copyLabels(g.Labels),
			Services:             svcs,
			CommandRules:         cmds,
			DefaultCommandAction: dca,
		})
	}
	return out, nil
}

func normalizeUsers(raw []rawUser, allowEnv bool) ([]User, error) {
	out := make([]User, 0, len(raw))
	seen := map[string]struct{}{}
	for i, u := range raw {
		path := indexPath("users", i)
		if u.ID == "" {
			return nil, yamlErrorAt(path+".id", "id is required")
		}
		id, err := precis.UsernameCasePreserved.String(u.ID)
		if err != nil || id == "" {
			return nil, yamlErrorAt(path+".id", "id is not a valid UsernameCasePreserved identifier")
		}
		if _, ok := seen[id]; ok {
			return nil, yamlErrorAt(path+".id", "duplicate user id")
		}
		seen[id] = struct{}{}
		rules, err := normalizeRuleSet(u.Rules, path+".rules")
		if err != nil {
			return nil, err
		}
		login, err := normalizeSecretRef(u.Credentials.Login.Verifier, credentials.PurposeLoginVerifier, path+".credentials.login.verifier", allowEnv)
		if err != nil {
			return nil, err
		}
		chal, err := normalizeSecretRef(u.Credentials.Challenge.Secret, credentials.PurposeChallengeSecret, path+".credentials.challenge.secret", allowEnv)
		if err != nil {
			return nil, err
		}
		en, err := normalizeSecretRef(u.Credentials.Enable.Verifier, credentials.PurposeEnableVerifier, path+".credentials.enable.verifier", allowEnv)
		if err != nil {
			return nil, err
		}
		out = append(out, User{
			ID:          id,
			DisplayName: u.DisplayName,
			Enabled:     boolOr(u.Enabled, true),
			Labels:      copyLabels(u.Labels),
			GroupIDs:    copyStrings(u.GroupIDs),
			Rules:       rules,
			Credentials: UserCredentials{
				Login:     LoginCred{Verifier: login},
				Challenge: ChallengeCred{Secret: chal},
				Enable:    EnableCred{Verifier: en},
			},
			Restrictions: UserRestrictions{
				ClientIDs:   copyStrings(u.Restrictions.ClientIDs),
				ValidAfter:  cloneTime(u.Restrictions.ValidAfter),
				ValidBefore: cloneTime(u.Restrictions.ValidBefore),
			},
			MustChangeLogin:  boolOr(u.MustChangeLogin, false),
			MustChangeEnable: boolOr(u.MustChangeEnable, false),
		})
	}
	return out, nil
}

func normalizeGroupsV2(raw []rawGroupV2) ([]Group, error) {
	base := make([]rawGroup, len(raw))
	for i, g := range raw {
		base[i] = g.rawGroup
	}
	out, err := normalizeGroups(base)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].RADIUSPolicyID = strings.TrimSpace(raw[i].RADIUSPolicyID)
	}
	return out, nil
}

func normalizeUsersV2(raw []rawUserV2, allowEnv bool) ([]User, error) {
	base := make([]rawUser, len(raw))
	for i, u := range raw {
		base[i] = u.rawUser
	}
	out, err := normalizeUsers(base, allowEnv)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].RADIUSPolicyID = strings.TrimSpace(raw[i].RADIUSPolicyID)
	}
	return out, nil
}

func normalizeRuleSet(raw rawRuleSet, path string) (RuleSet, error) {
	svcs, err := normalizeServiceRules(raw.Services, path+".services")
	if err != nil {
		return RuleSet{}, err
	}
	cmds, err := normalizeCommandRules(raw.CommandRules, path+".command_rules")
	if err != nil {
		return RuleSet{}, err
	}
	return RuleSet{Services: svcs, CommandRules: cmds}, nil
}

func normalizeServiceRules(raw []rawServiceRule, path string) ([]ServiceRule, error) {
	out := make([]ServiceRule, 0, len(raw))
	for i, r := range raw {
		p := indexPath(path, i)
		if r.Service == "" {
			return nil, yamlErrorAt(p+".service", "service is required")
		}
		action, err := parseYAMLAction(r.Action, p+".action")
		if err != nil {
			return nil, err
		}
		attrs, err := normalizeReplyAttributes(r.ReplyAttributes, p+".reply_attributes")
		if err != nil {
			return nil, err
		}
		var proto *string
		if r.Protocol != nil {
			v := *r.Protocol
			proto = &v
		}
		out = append(out, ServiceRule{
			Service:         r.Service,
			Protocol:        proto,
			Action:          action,
			ReplyAttributes: attrs,
		})
	}
	return out, nil
}

func normalizeCommandRules(raw []rawCommandRule, path string) ([]CommandRule, error) {
	out := make([]CommandRule, 0, len(raw))
	seen := map[string]struct{}{}
	for i, r := range raw {
		p := indexPath(path, i)
		if r.ID == "" {
			return nil, yamlErrorAt(p+".id", "id is required")
		}
		if _, ok := seen[r.ID]; ok {
			return nil, yamlErrorAt(p+".id", "duplicate command rule id")
		}
		seen[r.ID] = struct{}{}
		action, err := parseYAMLAction(r.Action, p+".action")
		if err != nil {
			return nil, err
		}
		cmd, err := normalizeStringMatch(r.Command, p+".command")
		if err != nil {
			return nil, err
		}
		args, err := normalizeStringMatch(r.Arguments, p+".arguments")
		if err != nil {
			return nil, err
		}
		out = append(out, CommandRule{
			ID:        r.ID,
			Priority:  intOr(r.Priority, 0),
			Action:    action,
			Command:   cmd,
			Arguments: args,
			Reason:    r.Reason,
		})
	}
	return out, nil
}

func normalizeStringMatch(raw rawStringMatch, path string) (StringMatch, error) {
	var exact, pattern string
	if raw.Exact != nil {
		exact = *raw.Exact
	}
	if raw.Pattern != nil {
		pattern = *raw.Pattern
	}
	switch {
	case exact != "" && pattern != "":
		return StringMatch{}, yamlErrorAt(path, "exactly one of exact or pattern is required")
	case exact == "" && pattern == "":
		return StringMatch{}, yamlErrorAt(path, "exactly one of exact or pattern is required")
	default:
		return StringMatch{Exact: exact, Pattern: pattern}, nil
	}
}

func normalizeReplyAttributes(raw []rawReplyAttribute, path string) (domain.AVPairs, error) {
	out := make(domain.AVPairs, 0, len(raw))
	for i, a := range raw {
		p := indexPath(path, i)
		sep := byte(domain.AVSepMandatory)
		switch a.Separator {
		case "", "=":
			sep = domain.AVSepMandatory
		case "*":
			sep = domain.AVSepOptional
		default:
			return nil, yamlErrorAt(p+".separator", "separator must be = or *")
		}
		pair := domain.AVPair{Name: a.Name, Separator: sep, Value: a.Value}
		if err := pair.Validate(); err != nil {
			return nil, yamlErrorAt(p, "invalid reply attribute")
		}
		out = append(out, pair)
	}
	return out, nil
}

func normalizeDefaultCommandAction(raw *string, path string) (domain.AuthorDecision, error) {
	if raw == nil {
		return domain.DecisionDeny, nil
	}
	v := strings.ToLower(strings.TrimSpace(*raw))
	if v != string(domain.DecisionDeny) {
		return "", yamlErrorAt(path, "default_command_action must be deny")
	}
	return domain.DecisionDeny, nil
}

// parseYAMLAction accepts the YAML-only permit alias as permit_add.
func parseYAMLAction(s, path string) (domain.AuthorDecision, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "permit", "permit_add":
		return domain.DecisionPermitAdd, nil
	case "permit_replace":
		return domain.DecisionPermitReplace, nil
	case "deny":
		return domain.DecisionDeny, nil
	case "":
		return "", yamlErrorAt(path, "action is required")
	default:
		return "", yamlErrorAt(path, "action must be permit, permit_add, permit_replace, or deny")
	}
}

func normalizeEvents(dst *Events, raw rawEvents) error {
	dst.RingBufferCapacity = intOr(raw.RingBufferCapacity, dst.RingBufferCapacity)
	dst.IncludeSuccessfulAuthentication = boolOr(raw.IncludeSuccessfulAuthentication, dst.IncludeSuccessfulAuthentication)
	dst.IncludeFailedAuthentication = boolOr(raw.IncludeFailedAuthentication, dst.IncludeFailedAuthentication)
	dst.IncludeAuthorization = boolOr(raw.IncludeAuthorization, dst.IncludeAuthorization)
	dst.IncludeAccounting = boolOr(raw.IncludeAccounting, dst.IncludeAccounting)
	dst.RedactUserInput = boolOr(raw.RedactUserInput, dst.RedactUserInput)
	dst.Stdout.Enabled = boolOr(raw.Stdout.Enabled, dst.Stdout.Enabled)
	if raw.Stdout.Format != "" {
		dst.Stdout.Format = raw.Stdout.Format
	}
	return nil
}

func normalizeObservability(dst *Observability, raw rawObservability) error {
	dst.Metrics.Enabled = boolOr(raw.Metrics.Enabled, dst.Metrics.Enabled)
	if raw.Metrics.Bind != "" {
		dst.Metrics.Bind = raw.Metrics.Bind
	}
	if raw.Metrics.Path != "" {
		dst.Metrics.Path = raw.Metrics.Path
	}
	dst.Metrics.ExposeOnAdmin = boolOr(raw.Metrics.ExposeOnAdmin, dst.Metrics.ExposeOnAdmin)
	dst.Tracing.Enabled = boolOr(raw.Tracing.Enabled, dst.Tracing.Enabled)
	dst.Profiling.Enabled = boolOr(raw.Profiling.Enabled, dst.Profiling.Enabled)
	return nil
}

func normalizeFileRef(raw *rawFileRef) FileRef {
	if raw == nil {
		return FileRef{}
	}
	return FileRef{File: raw.File}
}

func normalizeSecretRef(raw *rawSecretRef, purpose credentials.Purpose, path string, allowEnv bool) (SecretRef, error) {
	if raw == nil {
		return SecretRef{Purpose: purpose}, nil
	}
	file := strings.TrimSpace(raw.File)
	env := strings.TrimSpace(raw.Environment)
	switch {
	case file != "" && env != "":
		return SecretRef{}, yamlErrorAt(path, "secret reference must set exactly one of file or environment")
	case file == "" && env == "":
		return SecretRef{}, yamlErrorAt(path, "secret reference requires file or environment")
	case env != "" && !allowEnv:
		return SecretRef{}, yamlErrorAt(path, "environment secret references are disabled")
	}
	return SecretRef{
		Purpose:                 purpose,
		File:                    file,
		Environment:             env,
		PreserveTrailingNewline: boolOr(raw.PreserveTrailingNewline, false),
	}, nil
}

func normalizeCIDRs(in []string, path string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for i, s := range in {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, yamlErrorAt(indexPath(path, i), "invalid CIDR")
		}
		out = append(out, n.String())
	}
	return out, nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

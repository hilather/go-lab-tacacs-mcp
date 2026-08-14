package config

import (
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func normalizeV2(raw *rawFileV2) (*Document, error) {
	doc := defaultDocument()
	doc.SchemaVersion = SchemaVersionV2
	doc.Metadata = Metadata{
		Name:        raw.Metadata.Name,
		Description: raw.Metadata.Description,
		Labels:      copyLabels(raw.Metadata.Labels),
	}

	if err := normalizeServer(&doc.Server, raw.Server.rawServer); err != nil {
		return nil, err
	}
	doc.Server.AdminOnly = boolOr(raw.Server.AdminOnly, false)

	if err := normalizeRuntime(&doc.Runtime, raw.Runtime); err != nil {
		return nil, err
	}
	if err := normalizeSecurity(&doc.Security, raw.Security.rawSecurity); err != nil {
		return nil, err
	}
	// RADIUS policy defaults copy the effective legacy policy, then overlay.
	doc.Security.RADIUSSharedSecrets = doc.Security.LegacySharedSecrets
	if raw.Security.RADIUSSharedSecrets != nil {
		if err := applySharedSecretPolicy(&doc.Security.RADIUSSharedSecrets, *raw.Security.RADIUSSharedSecrets, "security.radius_shared_secrets"); err != nil {
			return nil, err
		}
	}

	if err := normalizeListeners(&doc.Listeners, rawListeners{
		LegacyTACACS: raw.Listeners.TACACS.Legacy,
		SecureTACACS: raw.Listeners.TACACS.TLS,
		HTTP:         raw.Listeners.HTTP,
	}, v2ListenerPaths, doc.Security.AllowEnvironmentSecrets); err != nil {
		return nil, err
	}
	if err := normalizeRADIUSAccess(&doc.Listeners.RADIUSAccess, raw.Listeners.RADIUS.Access, "listeners.radius.access"); err != nil {
		return nil, err
	}
	if err := normalizeRADIUSAccounting(&doc.Listeners.RADIUSAccounting, raw.Listeners.RADIUS.Accounting, "listeners.radius.accounting"); err != nil {
		return nil, err
	}

	if err := normalizeAPI(&doc.API, raw.API, doc.Listeners.HTTP.TLS.Enabled, doc.Security.AllowEnvironmentSecrets); err != nil {
		return nil, err
	}
	if err := normalizeLimits(&doc.Limits, raw.Limits); err != nil {
		return nil, err
	}

	clients, err := normalizeClientsV2(raw.Clients, doc.Security.AllowEnvironmentSecrets, doc.Listeners.RADIUSAccess)
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

	profiles, err := normalizeRADIUSReplyProfiles(raw.RADIUSReplyProfiles)
	if err != nil {
		return nil, err
	}
	doc.RADIUSReplyProfiles = profiles

	policies, err := normalizeRADIUSPolicies(raw.RADIUSPolicies)
	if err != nil {
		return nil, err
	}
	doc.RADIUSPolicies = policies
	doc.FallbackRADIUSPolicyID = strings.TrimSpace(raw.FallbackRADIUSPolicyID)

	if err := normalizeEvents(&doc.Events, raw.Events); err != nil {
		return nil, err
	}
	if err := normalizeObservability(&doc.Observability, raw.Observability); err != nil {
		return nil, err
	}
	return &doc, nil
}

func normalizeRADIUSAccess(dst *RADIUSListener, raw rawRADIUSAccess, path string) error {
	if err := normalizeRADIUSCommon(dst, raw.rawRADIUSCommon, path); err != nil {
		return err
	}
	if raw.MessageAuthenticator != "" {
		switch raw.MessageAuthenticator {
		case RADIUSMessageAuthenticatorRequired, RADIUSMessageAuthenticatorAllowMissing:
			dst.MessageAuthenticator = raw.MessageAuthenticator
		default:
			return yamlErrorAt(path+".message_authenticator", "message_authenticator must be required or allow_missing")
		}
	}
	dst.LimitProxyState = boolOr(raw.LimitProxyState, dst.LimitProxyState)
	return nil
}

func normalizeRADIUSAccounting(dst *RADIUSListener, raw rawRADIUSAccounting, path string) error {
	if err := normalizeRADIUSCommon(dst, raw.rawRADIUSCommon, path); err != nil {
		return err
	}
	dst.JournalEntries = intOr(raw.JournalEntries, dst.JournalEntries)
	n, err := parseByteSizeOr(raw.JournalBytes, path+".journal_bytes", dst.JournalBytes)
	if err != nil {
		return err
	}
	dst.JournalBytes = n
	dst.AmbiguousAccountingPerMinute = intOr(raw.AmbiguousAccountingPerMinute, dst.AmbiguousAccountingPerMinute)
	return nil
}

func normalizeRADIUSCommon(dst *RADIUSListener, raw rawRADIUSCommon, path string) error {
	dst.Enabled = boolOr(raw.Enabled, dst.Enabled)
	dst.Required = boolOr(raw.Required, dst.Required)
	if raw.Bind != "" {
		dst.Bind = raw.Bind
	}
	if raw.Transport != "" {
		if raw.Transport != RADIUSTransportUDP {
			return yamlErrorAt(path+".transport", "transport must be udp")
		}
		dst.Transport = raw.Transport
	}
	dst.MaxPacketBytes = intOr(raw.MaxPacketBytes, dst.MaxPacketBytes)
	dst.QueueCapacity = intOr(raw.QueueCapacity, dst.QueueCapacity)
	dst.Workers = intOr(raw.Workers, dst.Workers)
	var err error
	if dst.WorkerDeadline, err = parseDurationOr(raw.WorkerDeadline, path+".worker_deadline", dst.WorkerDeadline); err != nil {
		return err
	}
	dst.RetransmissionCacheEntries = intOr(raw.RetransmissionCacheEntries, dst.RetransmissionCacheEntries)
	if dst.RetransmissionCacheBytes, err = parseByteSizeOr(raw.RetransmissionCacheBytes, path+".retransmission_cache_bytes", dst.RetransmissionCacheBytes); err != nil {
		return err
	}
	if dst.RetransmissionTTL, err = parseDurationOr(raw.RetransmissionTTL, path+".retransmission_ttl", dst.RetransmissionTTL); err != nil {
		return err
	}
	dst.PerSourceRate = floatOr(raw.PerSourceRate, dst.PerSourceRate)
	dst.PerSourceBurst = intOr(raw.PerSourceBurst, dst.PerSourceBurst)
	return nil
}

func normalizeClientsV2(raw []rawClientV2, allowEnv bool, access RADIUSListener) ([]Client, error) {
	flat := make([]rawClient, len(raw))
	for i, c := range raw {
		flat[i] = c.rawClient
	}
	// Flatten first without synthesizing; endpoints are canonical when present.
	out, err := normalizeClientsFlatten(flat, allowEnv)
	if err != nil {
		return nil, err
	}
	for i, c := range raw {
		if len(c.Endpoints) == 0 {
			continue
		}
		path := indexPath("clients", i)
		eps, err := normalizeEndpoints(c.Endpoints, path, allowEnv, access, out[i])
		if err != nil {
			return nil, err
		}
		if flattenProtocolSpecified(c.rawClient) && !projectionMatchesClient(out[i], projectTACACS(eps)) {
			return nil, domain.NewError(domain.CodeClientEndpointProjectionMismatch, "client TACACS fields do not match endpoints").WithPath(path)
		}
		out[i].Endpoints = eps
		applyTACACSProjection(&out[i])
	}
	finalizeMissingEndpoints(out)
	return out, nil
}

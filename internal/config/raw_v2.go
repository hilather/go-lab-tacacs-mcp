package config

// Schema version 2 syntax model. Unknown fields still fail via inspectNode.

type rawFileV2 struct {
	SchemaVersion *int             `yaml:"schema_version"`
	Metadata      rawMetadata      `yaml:"metadata"`
	Server        rawServerV2      `yaml:"server"`
	Runtime       rawRuntime       `yaml:"runtime"`
	Security      rawSecurityV2    `yaml:"security"`
	Listeners     rawListenersV2   `yaml:"listeners"`
	API           rawAPI           `yaml:"api"`
	Limits        rawLimits        `yaml:"limits"`
	Clients       []rawClientV2    `yaml:"clients"`
	Groups        []rawGroup       `yaml:"groups"`
	Users         []rawUser        `yaml:"users"`
	FallbackRules rawRuleSet       `yaml:"fallback_rules"`
	Events        rawEvents        `yaml:"events"`
	Observability rawObservability `yaml:"observability"`
}

type rawServerV2 struct {
	rawServer `yaml:",inline"`
	AdminOnly *bool `yaml:"admin_only"`
}

type rawSecurityV2 struct {
	rawSecurity         `yaml:",inline"`
	RADIUSSharedSecrets *rawSharedSecretPolicy `yaml:"radius_shared_secrets"`
}

type rawListenersV2 struct {
	TACACS rawTACACSListenersV2 `yaml:"tacacs"`
	RADIUS rawRADIUSListenersV2 `yaml:"radius"`
	HTTP   rawHTTPListener      `yaml:"http"`
}

type rawTACACSListenersV2 struct {
	Legacy rawTACACSListener `yaml:"legacy"`
	TLS    rawSecureTACACS   `yaml:"tls"`
}

type rawRADIUSListenersV2 struct {
	Access     rawRADIUSAccess     `yaml:"access"`
	Accounting rawRADIUSAccounting `yaml:"accounting"`
}

type rawRADIUSCommon struct {
	Enabled                    *bool    `yaml:"enabled"`
	Required                   *bool    `yaml:"required"`
	Bind                       string   `yaml:"bind"`
	Transport                  string   `yaml:"transport"`
	MaxPacketBytes             *int     `yaml:"max_packet_bytes"`
	QueueCapacity              *int     `yaml:"queue_capacity"`
	Workers                    *int     `yaml:"workers"`
	WorkerDeadline             string   `yaml:"worker_deadline"`
	RetransmissionCacheEntries *int     `yaml:"retransmission_cache_entries"`
	RetransmissionCacheBytes   string   `yaml:"retransmission_cache_bytes"`
	RetransmissionTTL          string   `yaml:"retransmission_ttl"`
	PerSourceRate              *float64 `yaml:"per_source_rate"`
	PerSourceBurst             *int     `yaml:"per_source_burst"`
}

type rawRADIUSAccess struct {
	rawRADIUSCommon      `yaml:",inline"`
	MessageAuthenticator string `yaml:"message_authenticator"`
	LimitProxyState      *bool  `yaml:"limit_proxy_state"`
}

type rawRADIUSAccounting struct {
	rawRADIUSCommon              `yaml:",inline"`
	JournalEntries               *int   `yaml:"journal_entries"`
	JournalBytes                 string `yaml:"journal_bytes"`
	AmbiguousAccountingPerMinute *int   `yaml:"ambiguous_accounting_per_minute"`
}

// rawClientV2 adds endpoints[] on schema 2. v1 rawClient rejects that field.
type rawClientV2 struct {
	rawClient `yaml:",inline"`
	Endpoints []rawClientEndpoint `yaml:"endpoints"`
}

type rawClientEndpoint struct {
	ID        string             `yaml:"id"`
	Protocol  string             `yaml:"protocol"`
	Transport string             `yaml:"transport"`
	Roles     []string           `yaml:"roles"`
	TACACS    *rawTACACSEndpoint `yaml:"tacacs"`
	RADIUS    *rawRADIUSEndpoint `yaml:"radius"`
}

type rawTACACSEndpoint struct {
	SharedSecret          *rawSecretRef          `yaml:"shared_secret"`
	SharedSecretLifecycle rawSecretLifecycleMeta `yaml:"shared_secret_lifecycle"`
	AllowedMethods        []string               `yaml:"allowed_methods"`
	DefaultService        string                 `yaml:"default_service"`
	DefaultGroupIDs       []string               `yaml:"default_group_ids"`
	Accounting            rawClientAcct          `yaml:"accounting"`
}

type rawRADIUSEndpoint struct {
	SharedSecret                 *rawSecretRef          `yaml:"shared_secret"`
	SharedSecretLifecycle        rawSecretLifecycleMeta `yaml:"shared_secret_lifecycle"`
	RequireMessageAuthenticator  *bool                  `yaml:"require_message_authenticator"`
	LimitProxyState              *bool                  `yaml:"limit_proxy_state"`
	AllowedAuthenticationMethods []string               `yaml:"allowed_authentication_methods"`
	AccessPolicyID               string                 `yaml:"access_policy_id"`
	Accounting                   rawRADIUSEndpointAcct  `yaml:"accounting"`
}

type rawRADIUSEndpointAcct struct {
	AcceptStatusTypes []string `yaml:"accept_status_types"`
}

package config

// Schema version 2 syntax model. Unknown fields still fail via inspectNode.

type rawFileV2 struct {
	SchemaVersion          *int                    `yaml:"schema_version"`
	Metadata               rawMetadata             `yaml:"metadata"`
	Server                 rawServerV2             `yaml:"server"`
	Runtime                rawRuntime              `yaml:"runtime"`
	Security               rawSecurityV2           `yaml:"security"`
	Listeners              rawListenersV2          `yaml:"listeners"`
	API                    rawAPI                  `yaml:"api"`
	Limits                 rawLimits               `yaml:"limits"`
	Clients                []rawClientV2           `yaml:"clients"`
	Groups                 []rawGroupV2            `yaml:"groups"`
	Users                  []rawUserV2             `yaml:"users"`
	FallbackRules          rawRuleSet              `yaml:"fallback_rules"`
	RADIUSReplyProfiles    []rawRADIUSReplyProfile `yaml:"radius_reply_profiles"`
	RADIUSPolicies         []rawRADIUSPolicy       `yaml:"radius_policies"`
	FallbackRADIUSPolicyID string                  `yaml:"fallback_radius_policy_id"`
	Events                 rawEvents               `yaml:"events"`
	Observability          rawObservability        `yaml:"observability"`
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
	ChallengeTTL         string `yaml:"challenge_ttl"`
	ChallengeEntries     *int   `yaml:"challenge_entries"`
	ChallengeBytes       string `yaml:"challenge_bytes"`
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

type rawRADIUSPolicy struct {
	ID    string          `yaml:"id"`
	Rules []rawRADIUSRule `yaml:"rules"`
}

type rawRADIUSRule struct {
	ID            string         `yaml:"id"`
	Enabled       *bool          `yaml:"enabled"`
	Match         rawRADIUSMatch `yaml:"match"`
	Effect        string         `yaml:"effect"`
	ReplyProfiles []string       `yaml:"reply_profiles"`
}

type rawRADIUSMatch struct {
	GroupsAny  []string             `yaml:"groups_any"`
	Method     string               `yaml:"method"`
	Attributes []rawRADIUSAttrMatch `yaml:"attributes"`
}

type rawRADIUSAttrMatch struct {
	Name     string  `yaml:"name"`
	Vendor   *uint32 `yaml:"vendor"`
	Code     *int    `yaml:"code"`
	Op       string  `yaml:"op"`
	Value    string  `yaml:"value"`
	ValueHex string  `yaml:"value_hex"`
}

type rawRADIUSReplyProfile struct {
	ID         string               `yaml:"id"`
	Attributes []rawRADIUSReplyAttr `yaml:"attributes"`
}

type rawRADIUSReplyAttr struct {
	Name     string  `yaml:"name"`
	Vendor   *uint32 `yaml:"vendor"`
	Code     *int    `yaml:"code"`
	Value    string  `yaml:"value"`
	ValueHex string  `yaml:"value_hex"`
}

// rawUserV2 adds radius_policy_id on schema 2. v1 rawUser rejects that field.
type rawUserV2 struct {
	rawUser        `yaml:",inline"`
	RADIUSPolicyID string `yaml:"radius_policy_id"`
}

// rawGroupV2 adds radius_policy_id on schema 2. v1 rawGroup rejects that field.
type rawGroupV2 struct {
	rawGroup       `yaml:",inline"`
	RADIUSPolicyID string `yaml:"radius_policy_id"`
}

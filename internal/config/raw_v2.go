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
	Clients       []rawClient      `yaml:"clients"`
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

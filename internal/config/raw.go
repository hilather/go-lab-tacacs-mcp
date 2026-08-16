package config

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"gopkg.in/yaml.v3"
)

// YAML syntax types stay unexported.

// rawFile is the schema_version: 1 syntax model.
type rawFile struct {
	SchemaVersion *int             `yaml:"schema_version"`
	Metadata      rawMetadata      `yaml:"metadata"`
	Server        rawServer        `yaml:"server"`
	Runtime       rawRuntime       `yaml:"runtime"`
	Security      rawSecurity      `yaml:"security"`
	Listeners     rawListeners     `yaml:"listeners"`
	API           rawAPI           `yaml:"api"`
	Limits        rawLimits        `yaml:"limits"`
	Clients       []rawClient      `yaml:"clients"`
	Groups        []rawGroup       `yaml:"groups"`
	Users         []rawUser        `yaml:"users"`
	FallbackRules rawRuleSet       `yaml:"fallback_rules"`
	Events        rawEvents        `yaml:"events"`
	Observability rawObservability `yaml:"observability"`
}

// rawFileV1 is the schema_version: 1 syntax model (alias of rawFile).
type rawFileV1 = rawFile

type rawMetadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Labels      map[string]string `yaml:"labels"`
}

type rawServer struct {
	InstanceID         string `yaml:"instance_id"`
	ShutdownGrace      string `yaml:"shutdown_grace"`
	StartupFailureMode string `yaml:"startup_failure_mode"`
	LogLevel           string `yaml:"log_level"`
}

type rawRuntime struct {
	Persistence            string        `yaml:"persistence"`
	AllowShadowing         *bool         `yaml:"allow_shadowing"`
	DeleteBaselineBehavior string        `yaml:"delete_baseline_behavior"`
	ReloadOverlayBehavior  string        `yaml:"reload_overlay_behavior"`
	ResetRequiresScope     string        `yaml:"reset_requires_scope"`
	MaxObjects             rawMaxObjects `yaml:"max_objects"`
}

type rawMaxObjects struct {
	Users     *int `yaml:"users"`
	Groups    *int `yaml:"groups"`
	Clients   *int `yaml:"clients"`
	APITokens *int `yaml:"api_tokens"`
}

type rawSecurity struct {
	AllowEnvironmentSecrets *bool                 `yaml:"allow_environment_secrets"`
	StrictSecretFiles       *bool                 `yaml:"strict_secret_files"`
	LegacySharedSecrets     rawSharedSecretPolicy `yaml:"legacy_shared_secrets"`
}

type rawSharedSecretPolicy struct {
	MinimumLengthCharacters *int   `yaml:"minimum_length_characters"`
	MinimumCharacterClasses *int   `yaml:"minimum_character_classes"`
	RejectKnownWeakValues   *bool  `yaml:"reject_known_weak_values"`
	WarnOnReuse             *bool  `yaml:"warn_on_reuse"`
	DefaultRotationInterval string `yaml:"default_rotation_interval"`
	RotationWarningBefore   string `yaml:"rotation_warning_before"`
}

type rawListeners struct {
	LegacyTACACS rawTACACSListener `yaml:"legacy_tacacs"`
	SecureTACACS rawSecureTACACS   `yaml:"secure_tacacs"`
	HTTP         rawHTTPListener   `yaml:"http"`
}

type rawTACACSListener struct {
	Enabled                  *bool            `yaml:"enabled"`
	Bind                     string           `yaml:"bind"`
	AdvertisedPort           *int             `yaml:"advertised_port"`
	ReadTimeout              string           `yaml:"read_timeout"`
	WriteTimeout             string           `yaml:"write_timeout"`
	IdleTimeout              string           `yaml:"idle_timeout"`
	HandshakeTimeout         string           `yaml:"handshake_timeout"`
	MaxConnections           *int             `yaml:"max_connections"`
	MaxSessionsPerConnection *int             `yaml:"max_sessions_per_connection"`
	MaxPacketBodyBytes       *int             `yaml:"max_packet_body_bytes"`
	SingleConnect            rawSingleConnect `yaml:"single_connect"`
}

type rawSecureTACACS struct {
	rawTACACSListener `yaml:",inline"`
	TLS               rawSecureTLS `yaml:"tls"`
}

type rawSingleConnect struct {
	Enabled     *bool  `yaml:"enabled"`
	MaxLifetime string `yaml:"max_lifetime"`
	IdleTimeout string `yaml:"idle_timeout"`
}

type rawSecureTLS struct {
	MinimumVersion       string               `yaml:"minimum_version"`
	Identities           rawTLSIdentities     `yaml:"identities"`
	ClientAuthentication string               `yaml:"client_authentication"`
	ClientCABundle       *rawFileRef          `yaml:"client_ca_bundle"`
	Revocation           rawRevocation        `yaml:"revocation"`
	SessionResumption    rawSessionResumption `yaml:"session_resumption"`
	RejectEarlyData      *bool                `yaml:"reject_early_data"`
}

type rawTLSIdentities struct {
	DefaultID  string          `yaml:"default_id"`
	RequireSNI *bool           `yaml:"require_sni"`
	Profiles   []rawTLSProfile `yaml:"profiles"`
}

type rawTLSProfile struct {
	ID               string        `yaml:"id"`
	ServerNames      []string      `yaml:"server_names"`
	CertificateChain *rawFileRef   `yaml:"certificate_chain"`
	PrivateKey       *rawSecretRef `yaml:"private_key"`
}

type rawRevocation struct {
	Mode      string      `yaml:"mode"`
	CRLBundle *rawFileRef `yaml:"crl_bundle"`
}

type rawSessionResumption struct {
	Enabled                 *bool  `yaml:"enabled"`
	TicketLifetime          string `yaml:"ticket_lifetime"`
	RecheckClientRevocation *bool  `yaml:"recheck_client_revocation"`
}

type rawHTTPListener struct {
	Enabled             *bool      `yaml:"enabled"`
	Bind                string     `yaml:"bind"`
	ReadHeaderTimeout   string     `yaml:"read_header_timeout"`
	ReadTimeout         string     `yaml:"read_timeout"`
	WriteTimeout        string     `yaml:"write_timeout"`
	IdleTimeout         string     `yaml:"idle_timeout"`
	MaxRequestBodyBytes *int64     `yaml:"max_request_body_bytes"`
	TrustedProxyCIDRs   []string   `yaml:"trusted_proxy_cidrs"`
	TLS                 rawHTTPTLS `yaml:"tls"`
}

type rawHTTPTLS struct {
	Enabled *bool `yaml:"enabled"`
}

type rawAPI struct {
	Mode            string              `yaml:"mode"`
	UISession       rawUISession        `yaml:"ui_session"`
	MCP             rawMCP              `yaml:"mcp"`
	BootstrapTokens []rawBootstrapToken `yaml:"bootstrap_tokens"`
	RateLimits      rawRateLimits       `yaml:"rate_limits"`
}

type rawUISession struct {
	Enabled        *bool  `yaml:"enabled"`
	Lifetime       string `yaml:"lifetime"`
	IdleTimeout    string `yaml:"idle_timeout"`
	CookieSecure   *bool  `yaml:"cookie_secure"`
	CookieSameSite string `yaml:"cookie_same_site"`
}

type rawMCP struct {
	AllowedOrigins     []string `yaml:"allowed_origins"`
	RequireOrigin      *bool    `yaml:"require_origin"`
	AllowLegacyClients *bool    `yaml:"allow_legacy_clients"`
}

type rawBootstrapToken struct {
	ID        string        `yaml:"id"`
	Token     *rawSecretRef `yaml:"token"`
	Scopes    []string      `yaml:"scopes"`
	ExpiresAt *time.Time    `yaml:"expires_at"`
}

type rawRateLimits struct {
	Enabled                          *bool    `yaml:"enabled"`
	PerTokenRequestsPerSecond        *float64 `yaml:"per_token_requests_per_second"`
	PerTokenBurst                    *int     `yaml:"per_token_burst"`
	UnauthenticatedRequestsPerSecond *float64 `yaml:"unauthenticated_requests_per_second"`
	UnauthenticatedBurst             *int     `yaml:"unauthenticated_burst"`
}

type rawLimits struct {
	MaxUsernameBytes          *int `yaml:"max_username_bytes"`
	MaxPortBytes              *int `yaml:"max_port_bytes"`
	MaxRemoteAddressBytes     *int `yaml:"max_remote_address_bytes"`
	MaxAuthenticationRounds   *int `yaml:"max_authentication_rounds"`
	MaxAuthorizationArguments *int `yaml:"max_authorization_arguments"`
	MaxArgumentBytes          *int `yaml:"max_argument_bytes"`
	MaxCommandBytes           *int `yaml:"max_command_bytes"`
	MaxPolicyTraceSteps       *int `yaml:"max_policy_trace_steps"`
	MaxEventPayloadBytes      *int `yaml:"max_event_payload_bytes"`
}

type rawClient struct {
	ID             string            `yaml:"id"`
	DisplayName    string            `yaml:"display_name"`
	Priority       *int              `yaml:"priority"`
	Enabled        *bool             `yaml:"enabled"`
	Labels         map[string]string `yaml:"labels"`
	Match          rawClientMatch    `yaml:"match"`
	Legacy         rawClientLegacy   `yaml:"legacy"`
	Authentication rawClientAuth     `yaml:"authentication"`
	Authorization  rawClientAuthz    `yaml:"authorization"`
	Accounting     rawClientAcct     `yaml:"accounting"`
}

type rawClientMatch struct {
	SourceCIDRs []string     `yaml:"source_cidrs"`
	Transports  []string     `yaml:"transports"`
	Mode        string       `yaml:"mode"`
	Certificate rawCertMatch `yaml:"certificate"`
}

type rawCertMatch struct {
	DNSSANs []string `yaml:"dns_sans"`
	IPSANs  []string `yaml:"ip_sans"`
}

type rawClientLegacy struct {
	SharedSecret          *rawSecretRef          `yaml:"shared_secret"`
	SharedSecretLifecycle rawSecretLifecycleMeta `yaml:"shared_secret_lifecycle"`
}

type rawSecretLifecycleMeta struct {
	LastRotatedAt    *time.Time `yaml:"last_rotated_at"`
	RotationInterval string     `yaml:"rotation_interval"`
}

type rawClientAuth struct {
	AllowedMethods []string `yaml:"allowed_methods"`
	DefaultService string   `yaml:"default_service"`
}

type rawClientAuthz struct {
	DefaultGroupIDs []string `yaml:"default_group_ids"`
}

type rawClientAcct struct {
	Enabled        *bool `yaml:"enabled"`
	AcceptStart    *bool `yaml:"accept_start"`
	AcceptStop     *bool `yaml:"accept_stop"`
	AcceptWatchdog *bool `yaml:"accept_watchdog"`
}

type rawGroup struct {
	ID                   string            `yaml:"id"`
	DisplayName          string            `yaml:"display_name"`
	Priority             *int              `yaml:"priority"`
	Enabled              *bool             `yaml:"enabled"`
	Labels               map[string]string `yaml:"labels"`
	Services             []rawServiceRule  `yaml:"services"`
	CommandRules         []rawCommandRule  `yaml:"command_rules"`
	DefaultCommandAction *string           `yaml:"default_command_action"`
}

type rawRuleSet struct {
	Services     []rawServiceRule `yaml:"services"`
	CommandRules []rawCommandRule `yaml:"command_rules"`
}

type rawServiceRule struct {
	Service         string              `yaml:"service"`
	Protocol        *string             `yaml:"protocol"`
	Action          string              `yaml:"action"`
	ReplyAttributes []rawReplyAttribute `yaml:"reply_attributes"`
}

type rawReplyAttribute struct {
	Name      string `yaml:"name"`
	Separator string `yaml:"separator"`
	Value     string `yaml:"value"`
}

type rawCommandRule struct {
	ID        string         `yaml:"id"`
	Priority  *int           `yaml:"priority"`
	Action    string         `yaml:"action"`
	Command   rawStringMatch `yaml:"command"`
	Arguments rawStringMatch `yaml:"arguments"`
	Reason    string         `yaml:"reason"`
}

type rawStringMatch struct {
	Exact   *string `yaml:"exact"`
	Pattern *string `yaml:"pattern"`
}

type rawUser struct {
	ID               string              `yaml:"id"`
	DisplayName      string              `yaml:"display_name"`
	Enabled          *bool               `yaml:"enabled"`
	Labels           map[string]string   `yaml:"labels"`
	GroupIDs         []string            `yaml:"group_ids"`
	Rules            rawRuleSet          `yaml:"rules"`
	Credentials      rawUserCredentials  `yaml:"credentials"`
	Restrictions     rawUserRestrictions `yaml:"restrictions"`
	MustChangeLogin  *bool               `yaml:"must_change_login"`
	MustChangeEnable *bool               `yaml:"must_change_enable"`
}

type rawUserCredentials struct {
	Login     rawLoginCred     `yaml:"login"`
	Challenge rawChallengeCred `yaml:"challenge"`
	Enable    rawEnableCred    `yaml:"enable"`
}

type rawLoginCred struct {
	Verifier *rawSecretRef `yaml:"verifier"`
}

type rawChallengeCred struct {
	Secret *rawSecretRef `yaml:"secret"`
}

type rawEnableCred struct {
	Verifier *rawSecretRef `yaml:"verifier"`
}

type rawUserRestrictions struct {
	ClientIDs   []string   `yaml:"client_ids"`
	ValidAfter  *time.Time `yaml:"valid_after"`
	ValidBefore *time.Time `yaml:"valid_before"`
}

type rawEvents struct {
	RingBufferCapacity              *int           `yaml:"ring_buffer_capacity"`
	IncludeSuccessfulAuthentication *bool          `yaml:"include_successful_authentication"`
	IncludeFailedAuthentication     *bool          `yaml:"include_failed_authentication"`
	IncludeAuthorization            *bool          `yaml:"include_authorization"`
	IncludeAccounting               *bool          `yaml:"include_accounting"`
	RedactUserInput                 *bool          `yaml:"redact_user_input"`
	Stdout                          rawEventStdout `yaml:"stdout"`
}

type rawEventStdout struct {
	Enabled *bool  `yaml:"enabled"`
	Format  string `yaml:"format"`
}

type rawObservability struct {
	Metrics   rawMetrics `yaml:"metrics"`
	Tracing   rawToggle  `yaml:"tracing"`
	Profiling rawToggle  `yaml:"profiling"`
}

type rawMetrics struct {
	Enabled       *bool  `yaml:"enabled"`
	Bind          string `yaml:"bind"`
	Path          string `yaml:"path"`
	ExposeOnAdmin *bool  `yaml:"expose_on_admin"`
}

type rawToggle struct {
	Enabled *bool `yaml:"enabled"`
}

type rawFileRef struct {
	File string `yaml:"file"`
}

type rawSecretRef struct {
	File                    string `yaml:"file"`
	Environment             string `yaml:"environment"`
	PreserveTrailingNewline *bool  `yaml:"preserve_trailing_newline"`
}

func (r *rawSecretRef) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind == yaml.ScalarNode && isYAMLNull(value) {
		return nil
	}
	if value.Kind == yaml.ScalarNode {
		// Do not echo the scalar; it may be an embedded secret.
		return domain.NewError(domain.CodeConfigYAMLInvalid, "secret reference must be a mapping with file or environment")
	}
	if value.Kind != yaml.MappingNode {
		return domain.NewError(domain.CodeConfigYAMLInvalid, "secret reference must be a mapping with file or environment")
	}
	type plain rawSecretRef
	var p plain
	if err := value.Decode(&p); err != nil {
		return domain.NewError(domain.CodeConfigYAMLInvalid, "invalid secret reference")
	}
	*r = rawSecretRef(p)
	return nil
}

func (r *rawFileRef) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Kind == yaml.ScalarNode && isYAMLNull(value) {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return domain.NewError(domain.CodeConfigYAMLInvalid, "file reference must be a mapping with file")
	}
	type plain rawFileRef
	var p plain
	if err := value.Decode(&p); err != nil {
		return domain.NewError(domain.CodeConfigYAMLInvalid, "invalid file reference")
	}
	*r = rawFileRef(p)
	return nil
}

func isYAMLNull(n *yaml.Node) bool {
	if n == nil {
		return true
	}
	if n.Tag == "!!null" {
		return true
	}
	switch n.Value {
	case "", "null", "Null", "NULL", "~":
		return true
	default:
		return false
	}
}

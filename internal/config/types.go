package config

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const (
	// SchemaVersionV1 is the TACACS-shaped baseline syntax.
	SchemaVersionV1 = 1
	// SchemaVersionV2 is the named-listener syntax (RADIUS fields optional).
	SchemaVersionV2 = 2
	// SchemaVersion is the v1 source version. Kept so export and existing
	// callers continue to treat 1 as the default without emitting v2.
	SchemaVersion = SchemaVersionV1
)

// RADIUS listener transport and Message-Authenticator inherit defaults.
const (
	RADIUSTransportUDP                     = "udp"
	RADIUSMessageAuthenticatorRequired     = "required"
	RADIUSMessageAuthenticatorAllowMissing = "allow_missing"
	RADIUSMinPacketBytes                   = 20
	RADIUSMaxPacketBytes                   = 4096
	// v2 endpoint transport tokens are scoped by protocol, not domain.Transport.
	EndpointTransportTCP                 = "tcp"
	EndpointTransportTLS                 = "tls"
	EndpointTransportUDP                 = "udp"
	RADIUSAuthMethodPAP                  = "pap"
	RADIUSAuthMethodCHAP                 = "chap"
	RADIUSAuthMethodMSCHAPv1             = "mschapv1"
	RADIUSAuthMethodMSCHAPv2             = "mschapv2"
	RADIUSMatchOpEquals                  = "equals"
	RADIUSMatchOpPresent                 = "present"
	RADIUSMatchOpAbsent                  = "absent"
	RADIUSAcctStart                      = "start"
	RADIUSAcctStop                       = "stop"
	RADIUSAcctInterimUpdate              = "interim_update"
	RADIUSAcctAccountingOn               = "accounting_on"
	RADIUSAcctAccountingOff              = "accounting_off"
	RADIUSAccessRetransmissionTTLMin     = 5 * time.Second
	RADIUSAccessRetransmissionTTLMax     = 30 * time.Second
	RADIUSAccountingRetransmissionTTLMax = 300 * time.Second
	RADIUSChallengeTTLDefault            = 30 * time.Second
	RADIUSChallengeTTLMin                = 5 * time.Second
	RADIUSChallengeTTLMax                = 60 * time.Second
	RADIUSChallengeEntriesDefault        = 4096
	RADIUSChallengeEntriesMin            = 16
	RADIUSChallengeEntriesMax            = 65536
	RADIUSChallengeBytesDefault          = 1 << 20
	RADIUSChallengeBytesMin              = 64 << 10
	RADIUSChallengeBytesMax              = 8 << 20
	DefaultNASCoAPort                    = 3799
	DefaultCoATimeout                    = 3 * time.Second
	DefaultSessionIndexEntries           = 20000
	DefaultSessionIndexBytes             = 8 << 20
	DefaultSessionTTL                    = 24 * time.Hour
	MinSessionIndexEntries               = 16
	MaxSessionIndexEntries               = 100000
	MinSessionIndexBytes                 = 64 << 10
	MaxSessionIndexBytes                 = 64 << 20
	MinSessionTTL                        = time.Minute
	MaxSessionTTL                        = 24 * time.Hour
	MinCoATimeout                        = 500 * time.Millisecond
	MaxCoATimeout                        = 30 * time.Second
)

// DefaultMaxBytes is the default maximum baseline file size (4 MiB).
const DefaultMaxBytes = 4 << 20

// DefaultMaxSecretBytes is the default maximum secret-file size (1 MiB).
const DefaultMaxSecretBytes = 1 << 20

// Options controls Parse and Load limits.
type Options struct {
	// MaxBytes is the maximum accepted baseline size. Zero means DefaultMaxBytes.
	MaxBytes int64
}

// Document is the normalized baseline. YAML syntax types are not used here.
type Document struct {
	SchemaVersion int
	Metadata      Metadata
	Server        Server
	Runtime       Runtime
	Security      Security
	Listeners     Listeners
	API           API
	Limits        Limits
	Clients       []Client
	Groups        []Group
	Users         []User
	FallbackRules RuleSet
	// RADIUSPolicies, RADIUSReplyProfiles, FallbackRADIUSPolicyID, and
	// RADIUSDictionaries are schema v2 only. v1 documents keep them empty;
	// the v1 raw model still rejects the YAML keys.
	RADIUSPolicies         []RADIUSPolicy
	RADIUSReplyProfiles    []RADIUSReplyProfile
	FallbackRADIUSPolicyID string
	RADIUSDictionaries     []RADIUSDictionary
	Events                 Events
	Observability          Observability
}

// Metadata is descriptive and must not affect policy.
type Metadata struct {
	Name        string
	Description string
	Labels      map[string]string
}

// Server is process-wide lifecycle and logging.
type Server struct {
	InstanceID         string
	ShutdownGrace      time.Duration
	StartupFailureMode string
	// AdminOnly is accepted on schema v2 (default false). It is the only
	// way to start without an AAA listener.
	AdminOnly bool
	LogLevel  string
}

// Runtime is overlay policy. Persistence is memory in 1.0.
type Runtime struct {
	Persistence            string
	AllowShadowing         bool
	DeleteBaselineBehavior string
	ReloadOverlayBehavior  string
	ResetRequiresScope     string
	MaxObjects             MaxObjects
}

// MaxObjects caps overlay/baseline object counts before compilation.
type MaxObjects struct {
	Users     int
	Groups    int
	Clients   int
	APITokens int
}

// Security holds secret-reference and shared-secret policy.
type Security struct {
	AllowEnvironmentSecrets bool
	StrictSecretFiles       bool
	LegacySharedSecrets     SharedSecretPolicy
	// RADIUSSharedSecrets is the RADIUS secret policy. v1 documents copy
	// the effective legacy policy. RADIUS endpoint secrets use
	// credentials.PurposeRADIUSSharedSecret.
	RADIUSSharedSecrets SharedSecretPolicy
}

// SharedSecretPolicy is the global legacy shared-secret policy.
type SharedSecretPolicy struct {
	MinimumLengthCharacters int
	MinimumCharacterClasses int
	RejectKnownWeakValues   bool
	WarnOnReuse             bool
	DefaultRotationInterval time.Duration
	RotationWarningBefore   time.Duration
}

// Listeners is the named process sockets. RADIUS fields exist after v1
// migration and on v2 documents; both default to enabled:false. When
// enabled, cmd/taclabd registers the UDP sockets.
type Listeners struct {
	LegacyTACACS     TACACSListener
	SecureTACACS     SecureTACACSListener
	HTTP             HTTPListener
	RADIUSAccess     RADIUSListener
	RADIUSAccounting RADIUSListener
}

// RADIUSListener is a UDP access or accounting socket. Journal and
// ambiguous-accounting fields apply to accounting only.
type RADIUSListener struct {
	Enabled                      bool
	Required                     bool
	Bind                         string
	Transport                    string
	MaxPacketBytes               int
	QueueCapacity                int
	Workers                      int
	WorkerDeadline               time.Duration
	RetransmissionCacheEntries   int
	RetransmissionCacheBytes     int
	RetransmissionTTL            time.Duration
	JournalEntries               int
	JournalBytes                 int
	PerSourceRate                float64
	PerSourceBurst               int
	AmbiguousAccountingPerMinute int
	MessageAuthenticator         string
	LimitProxyState              bool
	// Challenge knobs apply to the access listener. Accounting ignores them.
	ChallengeTTL        time.Duration
	ChallengeEntries    int
	ChallengeBytes      int
	SessionIndexEntries int
	SessionIndexBytes   int
	SessionTTL          time.Duration
	CoATimeout          time.Duration
}

// TACACSListener is shared legacy/secure socket settings.
type TACACSListener struct {
	Enabled                  bool
	Bind                     string
	AdvertisedPort           int
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
	IdleTimeout              time.Duration
	HandshakeTimeout         time.Duration
	MaxConnections           int
	MaxSessionsPerConnection int
	MaxPacketBodyBytes       int
	SingleConnect            SingleConnect
}

// SecureTACACSListener is the TLS 1.3 TACACS socket.
type SecureTACACSListener struct {
	TACACSListener
	TLS SecureTLS
}

// SingleConnect is RFC 8907 multiplexing policy for one listener.
type SingleConnect struct {
	Enabled     bool
	MaxLifetime time.Duration
	IdleTimeout time.Duration
}

// SecureTLS is the secure TACACS TLS profile.
type SecureTLS struct {
	MinimumVersion       string
	Identities           TLSIdentities
	ClientAuthentication string
	ClientCABundle       FileRef
	Revocation           Revocation
	SessionResumption    SessionResumption
	RejectEarlyData      bool
}

// FileRef is a non-secret filesystem path (certificate chain, CRL, CA).
type FileRef struct {
	File string
}

// TLSIdentities is SNI profile selection.
type TLSIdentities struct {
	DefaultID  string
	RequireSNI bool
	Profiles   []TLSProfile
}

// TLSProfile is one certificate identity.
type TLSProfile struct {
	ID               string
	ServerNames      []string
	CertificateChain FileRef
	PrivateKey       SecretRef
}

// Revocation is CRL configuration.
type Revocation struct {
	Mode      string
	CRLBundle FileRef
}

// SessionResumption is TLS ticket policy.
type SessionResumption struct {
	Enabled                 bool
	TicketLifetime          time.Duration
	RecheckClientRevocation bool
}

// TLSTicketLifetimeEnforced is the only non-zero ticket_lifetime the
// pinned Go 1.24 crypto/tls stack can honor (maxSessionTicketLifetime).
// Zero disables tickets. Any other positive value is a configuration error
// (ADR-0005); the stack must not silently approximate.
const TLSTicketLifetimeEnforced = 7 * 24 * time.Hour

// HTTPListener is the admin REST/MCP/UI socket.
type HTTPListener struct {
	Enabled             bool
	Bind                string
	ReadHeaderTimeout   time.Duration
	WriteTimeout        time.Duration
	ReadTimeout         time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
	TrustedProxyCIDRs   []string
	TLS                 HTTPTLS
}

// HTTPTLS is optional admin TLS. CookieSecure follows Enabled when omitted.
type HTTPTLS struct {
	Enabled bool
}

// API is bootstrap tokens, UI session, MCP origin policy, and rate limits.
type API struct {
	Mode            string
	UISession       UISession
	MCP             MCP
	BootstrapTokens []BootstrapToken
	RateLimits      RateLimits
}

// UISession is the browser cookie session.
type UISession struct {
	Enabled        bool
	Lifetime       time.Duration
	IdleTimeout    time.Duration
	CookieSecure   bool
	CookieSameSite string
}

// MCP is Streamable HTTP origin policy.
// AllowedOrigins defaults to empty. The HTTP adapter may also allow the
// same-host UI origin when the UI is served. RequireOrigin defaults to false.
type MCP struct {
	AllowedOrigins []string
	RequireOrigin  bool
	// AllowLegacyClients relaxes the HTTP-level MCP-Protocol-Version pin so
	// older-generation clients (typically MCP gateways/proxies) can reach the
	// official SDK transport, which negotiates the protocol version during
	// initialize. Default false: the exact pinned header stays required.
	// subscriptions/listen always requires the pinned version.
	AllowLegacyClients bool
}

// BootstrapToken is a file-referenced lab bearer token.
type BootstrapToken struct {
	ID        string
	Token     SecretRef
	Scopes    []string
	ExpiresAt *time.Time
}

// RateLimits is the token-bucket policy.
type RateLimits struct {
	Enabled                          bool
	PerTokenRequestsPerSecond        float64
	PerTokenBurst                    int
	UnauthenticatedRequestsPerSecond float64
	UnauthenticatedBurst             int
}

// Limits are protocol security bounds.
type Limits struct {
	MaxUsernameBytes          int
	MaxPortBytes              int
	MaxRemoteAddressBytes     int
	MaxAuthenticationRounds   int
	MaxAuthorizationArguments int
	MaxArgumentBytes          int
	MaxCommandBytes           int
	MaxPolicyTraceSteps       int
	MaxEventPayloadBytes      int
}

// Client is a NAS or device group.
//
// Endpoints is the canonical protocol model after normalize. Match.Transports,
// Legacy, Authentication, Authorization, and Accounting are a deterministic
// projection of TACACS endpoints (v1 flatten fields, or v2 endpoints[]).
type Client struct {
	ID             string
	DisplayName    string
	Priority       int
	Enabled        bool
	Labels         map[string]string
	Match          ClientMatch
	Legacy         ClientLegacy
	Authentication ClientAuth
	Authorization  ClientAuthz
	Accounting     ClientAcct
	Endpoints      []ClientEndpoint
}

// ClientEndpoint is one protocol binding on a client. Exactly one of TACACS
// or RADIUS is set and must match Protocol.
type ClientEndpoint struct {
	ID        string
	Protocol  domain.Protocol
	Transport string
	Roles     []domain.ListenerRole
	TACACS    *TACACSEndpoint
	RADIUS    *RADIUSEndpoint
}

// TACACSEndpoint is the per-transport TACACS policy copied onto flatten fields.
type TACACSEndpoint struct {
	SharedSecret          SecretRef
	SharedSecretLifecycle SecretLifecycleMeta
	AllowedMethods        []AuthMethod
	DefaultService        domain.AuthenService
	DefaultGroupIDs       []string
	Accounting            ClientAcct
}

// RADIUSEndpoint is the UDP access/accounting profile. Access and accounting
// share this secret and compile into separate role indexes.
type RADIUSEndpoint struct {
	SharedSecret                 SecretRef
	SharedSecretLifecycle        SecretLifecycleMeta
	RequireMessageAuthenticator  bool
	LimitProxyState              bool
	AllowedAuthenticationMethods []string
	AccessPolicyID               string
	AcceptStatusTypes            []string
	NASCoAPort                   uint16
	CoADestination               string
}

// ClientMatch is identity selection input.
type ClientMatch struct {
	SourceCIDRs []string
	Transports  []domain.Transport
	Mode        domain.MatchMode
	Certificate CertMatch
}

// CertMatch is TLS SAN constraints.
type CertMatch struct {
	DNSSANs []string
	IPSANs  []string
}

// ClientLegacy is the RFC 8907 shared-secret block.
type ClientLegacy struct {
	SharedSecret          SecretRef
	SharedSecretLifecycle SecretLifecycleMeta
}

// SecretLifecycleMeta is non-secret rotation metadata.
type SecretLifecycleMeta struct {
	LastRotatedAt    *time.Time
	RotationInterval time.Duration
}

// AuthMethod is a configured authentication capability, including ENABLE
// and ASCII password-change which are not domain.AuthenType values.
type AuthMethod string

const (
	AuthMethodASCII       AuthMethod = "ascii"
	AuthMethodPAP         AuthMethod = "pap"
	AuthMethodCHAP        AuthMethod = "chap"
	AuthMethodMSCHAPv1    AuthMethod = "mschapv1"
	AuthMethodMSCHAPv2    AuthMethod = "mschapv2"
	AuthMethodEnable      AuthMethod = "enable"
	AuthMethodASCIIChpass AuthMethod = "ascii_chpass"
)

// ClientAuth is per-client authentication policy.
type ClientAuth struct {
	AllowedMethods []AuthMethod
	DefaultService domain.AuthenService
}

// ClientAuthz holds extra group membership appended after the user.
type ClientAuthz struct {
	DefaultGroupIDs []string
}

// ClientAcct is per-client accounting acceptance.
type ClientAcct struct {
	Enabled        bool
	AcceptStart    bool
	AcceptStop     bool
	AcceptWatchdog bool
}

// Group is a flat authorization group.
type Group struct {
	ID                   string
	DisplayName          string
	Priority             int
	Enabled              bool
	Labels               map[string]string
	Services             []ServiceRule
	CommandRules         []CommandRule
	DefaultCommandAction domain.AuthorDecision
	// RADIUSPolicyID is schema v2 only. Empty means no attached RADIUS policy.
	RADIUSPolicyID string
}

// RuleSet is the shared services + command_rules shape (groups, users, fallback).
type RuleSet struct {
	Services     []ServiceRule
	CommandRules []CommandRule
}

// ServiceRule is session/service authorization (empty cmd).
type ServiceRule struct {
	Service         string
	Protocol        *string
	Action          domain.AuthorDecision
	ReplyAttributes domain.AVPairs
}

// CommandRule is command authorization (non-empty cmd).
type CommandRule struct {
	ID        string
	Priority  int
	Action    domain.AuthorDecision
	Command   StringMatch
	Arguments StringMatch
	Reason    string
}

// StringMatch is exactly one of Exact or Pattern.
type StringMatch struct {
	Exact   string
	Pattern string
}

// RADIUSPolicy is a named first-match access policy (user, group, client, or fallback).
type RADIUSPolicy struct {
	ID    string
	Rules []RADIUSRule
}

// RADIUSRule is one access decision. Enabled defaults true; false skips the rule.
type RADIUSRule struct {
	ID            string
	Enabled       bool
	Match         RADIUSMatch
	Effect        domain.Effect
	ReplyProfiles []string
}

// RADIUSMatch is the frozen client/fallback dialect: groups_any, method, attributes.
// Empty GroupsAny or a nil Method is no constraint.
type RADIUSMatch struct {
	GroupsAny  []string
	Method     *domain.AuthMethod
	Attributes []RADIUSAttrMatch
}

// RADIUSAttrMatch is one typed request-attribute predicate.
// Name is an IETF dictionary name, or Vendor+Code identify a raw VSA / type code.
type RADIUSAttrMatch struct {
	Name     string
	Vendor   uint32
	Code     uint8
	Op       string
	Value    string
	ValueHex string
}

// RADIUSReplyProfile is a named ordered attribute list merged by permit rules.
type RADIUSReplyProfile struct {
	ID         string
	Attributes []RADIUSReplyAttr
}

// RADIUSDictionary is a v2 operator dictionary file reference (ADR 0026).
// Files are TacLab YAML, local, size-capped, and compiled fail-closed.
type RADIUSDictionary struct {
	ID      string
	File    string
	Enabled bool
}

// RADIUSReplyAttr is one policy/config reply attribute. No secret-bearing values.
// Name is an IETF dictionary name, or Vendor+Code+ValueHex emit a raw VSA.
type RADIUSReplyAttr struct {
	Name     string
	Vendor   uint32
	Code     uint8
	Value    string
	ValueHex string
}

// User is a TACACS identity. ID is UsernameCasePreserved.
type User struct {
	ID               string
	DisplayName      string
	Enabled          bool
	Labels           map[string]string
	GroupIDs         []string
	Rules            RuleSet
	Credentials      UserCredentials
	Restrictions     UserRestrictions
	MustChangeLogin  bool
	MustChangeEnable bool
	// RADIUSPolicyID is schema v2 only. Empty means no attached RADIUS policy.
	RADIUSPolicyID string
}

// UserCredentials holds typed secret references, not verifier bytes.
type UserCredentials struct {
	Login     LoginCred
	Challenge ChallengeCred
	Enable    EnableCred
}

// LoginCred is the ASCII/PAP verifier reference.
type LoginCred struct {
	Verifier SecretRef
}

// ChallengeCred is the CHAP/MS-CHAP secret reference.
type ChallengeCred struct {
	Secret SecretRef
}

// EnableCred is the ENABLE verifier reference.
type EnableCred struct {
	Verifier SecretRef
}

// UserRestrictions is client and time gates.
type UserRestrictions struct {
	ClientIDs   []string
	ValidAfter  *time.Time
	ValidBefore *time.Time
}

// Events is the in-memory ring and stdout sink.
type Events struct {
	RingBufferCapacity              int
	IncludeSuccessfulAuthentication bool
	IncludeFailedAuthentication     bool
	IncludeAuthorization            bool
	IncludeAccounting               bool
	RedactUserInput                 bool
	Stdout                          EventStdout
}

// EventStdout is the process-stdout event sink.
type EventStdout struct {
	Enabled bool
	Format  string
}

// Observability is metrics, tracing, and profiling.
type Observability struct {
	Metrics   Metrics
	Tracing   Toggle
	Profiling Toggle
}

// Metrics is the Prometheus scrape endpoint.
type Metrics struct {
	Enabled       bool
	Bind          string
	Path          string
	ExposeOnAdmin bool
}

// Toggle is a bare enabled flag.
type Toggle struct {
	Enabled bool
}

// SecretRef is a typed file, environment, or in-process overlay pointer.
// It never holds secret bytes. MemoryID is never present in YAML.
type SecretRef struct {
	Purpose                 credentials.Purpose
	File                    string
	Environment             string
	PreserveTrailingNewline bool
	MemoryID                string
}

// Set reports whether a source is present.
func (r SecretRef) Set() bool {
	return r.File != "" || r.Environment != "" || r.MemoryID != ""
}

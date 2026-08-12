package config

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// SchemaVersion is the only baseline version this loader accepts.
const SchemaVersion = 1

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
	Events        Events
	Observability Observability
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
	LogLevel           string
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

// Security holds secret-reference and legacy shared-secret policy.
type Security struct {
	AllowEnvironmentSecrets bool
	StrictSecretFiles       bool
	LegacySharedSecrets     SharedSecretPolicy
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

// Listeners is the three process sockets.
type Listeners struct {
	LegacyTACACS TACACSListener
	SecureTACACS SecureTACACSListener
	HTTP         HTTPListener
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

// User is a TACACS identity. ID is UsernameCasePreserved.
type User struct {
	ID           string
	DisplayName  string
	Enabled      bool
	Labels       map[string]string
	GroupIDs     []string
	Rules        RuleSet
	Credentials  UserCredentials
	Restrictions UserRestrictions
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

// SecretRef is a typed file or environment pointer. It never holds secret bytes.
type SecretRef struct {
	Purpose                 credentials.Purpose
	File                    string
	Environment             string
	PreserveTrailingNewline bool
}

// Set reports whether a source is present.
func (r SecretRef) Set() bool {
	return r.File != "" || r.Environment != ""
}

package operations

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const (
	defaultObjectPage = 100
	maxObjectPage     = 500
)

// ListUsersRequest lists users in id order.
type ListUsersRequest struct {
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// GetUserRequest fetches one user.
type GetUserRequest struct {
	ID             string `json:"id"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// CreateUserRequest creates a runtime user or an explicit baseline override.
type CreateUserRequest struct {
	ID               string             `json:"id"`
	DisplayName      *string            `json:"display_name,omitempty"`
	Enabled          *bool              `json:"enabled,omitempty"`
	Labels           *map[string]string `json:"labels,omitempty"`
	GroupIDs         *[]string          `json:"group_ids,omitempty"`
	Rules            *RuleSetView       `json:"rules,omitempty"`
	Login            OptionalSecret     `json:"login,omitempty"`
	Challenge        OptionalSecret     `json:"challenge,omitempty"`
	Enable           OptionalSecret     `json:"enable,omitempty"`
	Restrictions     *RestrictionsView  `json:"restrictions,omitempty"`
	MustChangeLogin  *bool              `json:"must_change_login,omitempty"`
	MustChangeEnable *bool              `json:"must_change_enable,omitempty"`
	RADIUSPolicyID   OptionalPolicyID   `json:"radius_policy_id,omitempty"`
	Override         bool               `json:"override,omitempty"`
}

// UpdateUserRequest is a typed user patch. Omitted fields are unchanged.
type UpdateUserRequest struct {
	ID               string             `json:"id"`
	DisplayName      *string            `json:"display_name,omitempty"`
	Enabled          *bool              `json:"enabled,omitempty"`
	Labels           *map[string]string `json:"labels,omitempty"`
	GroupIDs         *[]string          `json:"group_ids,omitempty"`
	Rules            *RuleSetView       `json:"rules,omitempty"`
	Login            OptionalSecret     `json:"login,omitempty"`
	Challenge        OptionalSecret     `json:"challenge,omitempty"`
	Enable           OptionalSecret     `json:"enable,omitempty"`
	Restrictions     *RestrictionsView  `json:"restrictions,omitempty"`
	MustChangeLogin  *bool              `json:"must_change_login,omitempty"`
	MustChangeEnable *bool              `json:"must_change_enable,omitempty"`
	RADIUSPolicyID   OptionalPolicyID   `json:"radius_policy_id,omitempty"`
}

// DeleteUserRequest deletes a runtime user or tombstones a baseline user.
type DeleteUserRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// User is the secret-free administrative view.
type User struct {
	ID                string              `json:"id"`
	DisplayName       string              `json:"display_name,omitempty"`
	Enabled           bool                `json:"enabled"`
	Source            domain.ObjectSource `json:"source"`
	ShadowsSource     domain.ObjectSource `json:"shadows_source,omitempty"`
	Deleted           bool                `json:"deleted,omitempty"`
	RevisionCreated   domain.Revision     `json:"revision_created"`
	RevisionUpdated   domain.Revision     `json:"revision_updated"`
	EffectiveRevision domain.Revision     `json:"effective_revision"`
	Labels            map[string]string   `json:"labels,omitempty"`
	GroupIDs          []string            `json:"group_ids,omitempty"`
	Rules             RuleSetView         `json:"rules"`
	Restrictions      RestrictionsView    `json:"restrictions"`
	// Capability flags are admin metadata from the snapshot, not a TACACS
	// username-enumeration guarantee.
	ASCIIPapConfigured  bool      `json:"ascii_pap_configured"`
	ChallengeConfigured bool      `json:"challenge_configured"`
	EnableConfigured    bool      `json:"enable_configured"`
	MustChangeLogin     bool      `json:"must_change_login"`
	MustChangeEnable    bool      `json:"must_change_enable"`
	RADIUSPolicyID      string    `json:"radius_policy_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (u User) envelopeRevision() domain.Revision { return u.EffectiveRevision }

// UserList is users.list output in id order.
type UserList struct {
	Revision   domain.Revision `json:"revision"`
	Items      []User          `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

func (u UserList) envelopeRevision() domain.Revision { return u.Revision }

// ListGroupsRequest lists groups in id order.
type ListGroupsRequest struct {
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// GetGroupRequest fetches one group.
type GetGroupRequest struct {
	ID             string `json:"id"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// CreateGroupRequest creates a runtime group or an explicit baseline override.
type CreateGroupRequest struct {
	ID                   string             `json:"id"`
	DisplayName          *string            `json:"display_name,omitempty"`
	Enabled              *bool              `json:"enabled,omitempty"`
	Priority             *int               `json:"priority,omitempty"`
	Labels               *map[string]string `json:"labels,omitempty"`
	Services             *[]ServiceRuleView `json:"services,omitempty"`
	CommandRules         *[]CommandRuleView `json:"command_rules,omitempty"`
	DefaultCommandAction *string            `json:"default_command_action,omitempty"`
	RADIUSPolicyID       OptionalPolicyID   `json:"radius_policy_id,omitempty"`
	Override             bool               `json:"override,omitempty"`
}

// UpdateGroupRequest is a typed group patch.
type UpdateGroupRequest struct {
	ID                   string             `json:"id"`
	DisplayName          *string            `json:"display_name,omitempty"`
	Enabled              *bool              `json:"enabled,omitempty"`
	Priority             *int               `json:"priority,omitempty"`
	Labels               *map[string]string `json:"labels,omitempty"`
	Services             *[]ServiceRuleView `json:"services,omitempty"`
	CommandRules         *[]CommandRuleView `json:"command_rules,omitempty"`
	DefaultCommandAction *string            `json:"default_command_action,omitempty"`
	RADIUSPolicyID       OptionalPolicyID   `json:"radius_policy_id,omitempty"`
}

// DeleteGroupRequest deletes a runtime group or tombstones a baseline group.
type DeleteGroupRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// Group is the administrative view.
type Group struct {
	ID                   string              `json:"id"`
	DisplayName          string              `json:"display_name,omitempty"`
	Enabled              bool                `json:"enabled"`
	Priority             int                 `json:"priority"`
	Source               domain.ObjectSource `json:"source"`
	ShadowsSource        domain.ObjectSource `json:"shadows_source,omitempty"`
	Deleted              bool                `json:"deleted,omitempty"`
	RevisionCreated      domain.Revision     `json:"revision_created"`
	RevisionUpdated      domain.Revision     `json:"revision_updated"`
	EffectiveRevision    domain.Revision     `json:"effective_revision"`
	Labels               map[string]string   `json:"labels,omitempty"`
	Services             []ServiceRuleView   `json:"services,omitempty"`
	CommandRules         []CommandRuleView   `json:"command_rules,omitempty"`
	DefaultCommandAction string              `json:"default_command_action,omitempty"`
	RADIUSPolicyID       string              `json:"radius_policy_id,omitempty"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

func (g Group) envelopeRevision() domain.Revision { return g.EffectiveRevision }

// GroupList is groups.list output in id order.
type GroupList struct {
	Revision   domain.Revision `json:"revision"`
	Items      []Group         `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

func (g GroupList) envelopeRevision() domain.Revision { return g.Revision }

// ListClientsRequest lists clients in id order.
type ListClientsRequest struct {
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// GetClientRequest fetches one client.
type GetClientRequest struct {
	ID             string `json:"id"`
	IncludeDeleted bool   `json:"include_deleted,omitempty"`
}

// CreateClientRequest creates a runtime client or an explicit baseline override.
type CreateClientRequest struct {
	ID                    string                 `json:"id"`
	DisplayName           *string                `json:"display_name,omitempty"`
	Enabled               *bool                  `json:"enabled,omitempty"`
	Priority              *int                   `json:"priority,omitempty"`
	Labels                *map[string]string     `json:"labels,omitempty"`
	Match                 *ClientMatchView       `json:"match,omitempty"`
	SharedSecret          OptionalSecret         `json:"shared_secret,omitempty"`
	SharedSecretLifecycle *LifecycleWrite        `json:"shared_secret_lifecycle,omitempty"`
	Authentication        *ClientAuthView        `json:"authentication,omitempty"`
	Authorization         *ClientAuthzView       `json:"authorization,omitempty"`
	Accounting            *ClientAcctView        `json:"accounting,omitempty"`
	Endpoints             *[]ClientEndpointWrite `json:"endpoints,omitempty"`
	RADIUS                *ClientRADIUSWrite     `json:"radius,omitempty"`
	Override              bool                   `json:"override,omitempty"`
}

// UpdateClientRequest is a typed client patch.
type UpdateClientRequest struct {
	ID                    string                 `json:"id"`
	DisplayName           *string                `json:"display_name,omitempty"`
	Enabled               *bool                  `json:"enabled,omitempty"`
	Priority              *int                   `json:"priority,omitempty"`
	Labels                *map[string]string     `json:"labels,omitempty"`
	Match                 *ClientMatchView       `json:"match,omitempty"`
	SharedSecret          OptionalSecret         `json:"shared_secret,omitempty"`
	SharedSecretLifecycle *LifecycleWrite        `json:"shared_secret_lifecycle,omitempty"`
	Authentication        *ClientAuthView        `json:"authentication,omitempty"`
	Authorization         *ClientAuthzView       `json:"authorization,omitempty"`
	Accounting            *ClientAcctView        `json:"accounting,omitempty"`
	Endpoints             *[]ClientEndpointWrite `json:"endpoints,omitempty"`
	RADIUS                *ClientRADIUSWrite     `json:"radius,omitempty"`
}

// DeleteClientRequest deletes a runtime client or tombstones a baseline client.
type DeleteClientRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// Client is the secret-free administrative view.
type Client struct {
	ID                     string               `json:"id"`
	DisplayName            string               `json:"display_name,omitempty"`
	Enabled                bool                 `json:"enabled"`
	Priority               int                  `json:"priority"`
	Source                 domain.ObjectSource  `json:"source"`
	ShadowsSource          domain.ObjectSource  `json:"shadows_source,omitempty"`
	Deleted                bool                 `json:"deleted,omitempty"`
	RevisionCreated        domain.Revision      `json:"revision_created"`
	RevisionUpdated        domain.Revision      `json:"revision_updated"`
	EffectiveRevision      domain.Revision      `json:"effective_revision"`
	Labels                 map[string]string    `json:"labels,omitempty"`
	Match                  ClientMatchView      `json:"match"`
	SharedSecretConfigured bool                 `json:"shared_secret_configured"`
	SharedSecretLifecycle  string               `json:"shared_secret_lifecycle"`
	Authentication         ClientAuthView       `json:"authentication"`
	Authorization          ClientAuthzView      `json:"authorization"`
	Accounting             ClientAcctView       `json:"accounting"`
	Protocols              ClientProtocolsView  `json:"protocols,omitempty"`
	Endpoints              []ClientEndpointView `json:"endpoints,omitempty"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
}

func (c Client) envelopeRevision() domain.Revision { return c.EffectiveRevision }

// ClientList is clients.list output in id order.
type ClientList struct {
	Revision   domain.Revision `json:"revision"`
	Items      []Client        `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

func (c ClientList) envelopeRevision() domain.Revision { return c.Revision }

// RuleSetView is services + command_rules on the wire.
type RuleSetView struct {
	Services     []ServiceRuleView `json:"services,omitempty" yaml:"services,omitempty"`
	CommandRules []CommandRuleView `json:"command_rules,omitempty" yaml:"command_rules,omitempty"`
}

// ServiceRuleView is one session/service rule. Action is permit_add, permit_replace, or deny.
type ServiceRuleView struct {
	Service         string          `json:"service" yaml:"service"`
	Protocol        *string         `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Action          string          `json:"action" yaml:"action"`
	ReplyAttributes []PolicyTraceAV `json:"reply_attributes,omitempty" yaml:"reply_attributes,omitempty"`
}

// CommandRuleView is one command rule.
type CommandRuleView struct {
	ID        string    `json:"id" yaml:"id"`
	Priority  int       `json:"priority" yaml:"priority"`
	Action    string    `json:"action" yaml:"action"`
	Command   MatchView `json:"command" yaml:"command"`
	Arguments MatchView `json:"arguments" yaml:"arguments"`
	Reason    string    `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// MatchView is exactly one of exact or pattern.
type MatchView struct {
	Exact   string `json:"exact,omitempty" yaml:"exact,omitempty"`
	Pattern string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
}

// RestrictionsView is client and time gates.
type RestrictionsView struct {
	ClientIDs   []string   `json:"client_ids,omitempty" yaml:"client_ids,omitempty"`
	ValidAfter  *time.Time `json:"valid_after,omitempty" yaml:"valid_after,omitempty"`
	ValidBefore *time.Time `json:"valid_before,omitempty" yaml:"valid_before,omitempty"`
}

// ClientMatchView is identity selection input.
type ClientMatchView struct {
	SourceCIDRs []string      `json:"source_cidrs,omitempty" yaml:"source_cidrs,omitempty"`
	Transports  []string      `json:"transports,omitempty" yaml:"transports,omitempty"`
	Mode        string        `json:"mode,omitempty" yaml:"mode,omitempty"`
	Certificate CertMatchView `json:"certificate" yaml:"certificate"`
}

// CertMatchView is TLS SAN constraints.
type CertMatchView struct {
	DNSSANs []string `json:"dns_sans,omitempty" yaml:"dns_sans,omitempty"`
	IPSANs  []string `json:"ip_sans,omitempty" yaml:"ip_sans,omitempty"`
}

// ClientAuthView is per-client authentication policy.
type ClientAuthView struct {
	AllowedMethods []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`
	DefaultService string   `json:"default_service,omitempty" yaml:"default_service,omitempty"`
}

// ClientAuthzView holds extra group membership appended after the user.
type ClientAuthzView struct {
	DefaultGroupIDs []string `json:"default_group_ids,omitempty" yaml:"default_group_ids,omitempty"`
}

// ClientAcctView is per-client accounting acceptance.
type ClientAcctView struct {
	Enabled        bool `json:"enabled" yaml:"enabled"`
	AcceptStart    bool `json:"accept_start" yaml:"accept_start"`
	AcceptStop     bool `json:"accept_stop" yaml:"accept_stop"`
	AcceptWatchdog bool `json:"accept_watchdog" yaml:"accept_watchdog"`
}

// ClientProtocolsView is the sanitized TACACS + RADIUS summary. Endpoints
// remain canonical; this block is a view of those endpoints.
type ClientProtocolsView struct {
	TACACS ClientTACACSProtocolView `json:"tacacs" yaml:"tacacs"`
	RADIUS ClientRADIUSProtocolView `json:"radius" yaml:"radius"`
}

// ClientTACACSProtocolView is the flattened TACACS capability summary.
type ClientTACACSProtocolView struct {
	LegacyEnabled          bool `json:"legacy_enabled" yaml:"legacy_enabled"`
	TLSEnabled             bool `json:"tls_enabled" yaml:"tls_enabled"`
	SharedSecretConfigured bool `json:"shared_secret_configured" yaml:"shared_secret_configured"`
}

// ClientRADIUSProtocolView is the flattened protocols.radius view.
type ClientRADIUSProtocolView struct {
	Enabled                     bool     `json:"enabled" yaml:"enabled"`
	Roles                       []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	SharedSecretConfigured      bool     `json:"shared_secret_configured" yaml:"shared_secret_configured"`
	SecretLifecycle             string   `json:"secret_lifecycle,omitempty" yaml:"secret_lifecycle,omitempty"`
	RequireMessageAuthenticator bool     `json:"require_message_authenticator" yaml:"require_message_authenticator"`
	LimitProxyState             bool     `json:"limit_proxy_state" yaml:"limit_proxy_state"`
	AllowedMethods              []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`
	AccessPolicyID              string   `json:"access_policy_id,omitempty" yaml:"access_policy_id,omitempty"`
	AcceptStatusTypes           []string `json:"accept_status_types,omitempty" yaml:"accept_status_types,omitempty"`
}

// ClientEndpointView is one canonical protocol binding without secret values.
type ClientEndpointView struct {
	ID        string                    `json:"id" yaml:"id"`
	Protocol  string                    `json:"protocol" yaml:"protocol"`
	Transport string                    `json:"transport" yaml:"transport"`
	Roles     []string                  `json:"roles,omitempty" yaml:"roles,omitempty"`
	TACACS    *ClientTACACSEndpointView `json:"tacacs,omitempty" yaml:"tacacs,omitempty"`
	RADIUS    *ClientRADIUSProtocolView `json:"radius,omitempty" yaml:"radius,omitempty"`
}

// ClientTACACSEndpointView is the sanitized TACACS endpoint policy.
type ClientTACACSEndpointView struct {
	SharedSecretConfigured bool           `json:"shared_secret_configured" yaml:"shared_secret_configured"`
	AllowedMethods         []string       `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`
	DefaultService         string         `json:"default_service,omitempty" yaml:"default_service,omitempty"`
	DefaultGroupIDs        []string       `json:"default_group_ids,omitempty" yaml:"default_group_ids,omitempty"`
	Accounting             ClientAcctView `json:"accounting" yaml:"accounting"`
}

// ClientEndpointWrite is the create/update form of one endpoint.
type ClientEndpointWrite struct {
	ID        string                     `json:"id"`
	Protocol  string                     `json:"protocol"`
	Transport string                     `json:"transport"`
	Roles     []string                   `json:"roles,omitempty"`
	TACACS    *ClientTACACSEndpointWrite `json:"tacacs,omitempty"`
	RADIUS    *ClientRADIUSWrite         `json:"radius,omitempty"`
}

// ClientTACACSEndpointWrite is the writable TACACS endpoint block.
type ClientTACACSEndpointWrite struct {
	SharedSecret          OptionalSecret  `json:"shared_secret,omitempty"`
	SharedSecretLifecycle *LifecycleWrite `json:"shared_secret_lifecycle,omitempty"`
	AllowedMethods        []string        `json:"allowed_methods,omitempty"`
	DefaultService        string          `json:"default_service,omitempty"`
	DefaultGroupIDs       []string        `json:"default_group_ids,omitempty"`
	Accounting            *ClientAcctView `json:"accounting,omitempty"`
}

// ClientRADIUSWrite is the flattened RADIUS create/update object.
type ClientRADIUSWrite struct {
	SharedSecret                OptionalSecret  `json:"shared_secret,omitempty"`
	SharedSecretLifecycle       *LifecycleWrite `json:"shared_secret_lifecycle,omitempty"`
	Enabled                     *bool           `json:"enabled,omitempty"`
	Roles                       []string        `json:"roles,omitempty"`
	RequireMessageAuthenticator *bool           `json:"require_message_authenticator,omitempty"`
	LimitProxyState             *bool           `json:"limit_proxy_state,omitempty"`
	AllowedMethods              []string        `json:"allowed_methods,omitempty"`
	AccessPolicyID              *string         `json:"access_policy_id,omitempty"`
	AcceptStatusTypes           []string        `json:"accept_status_types,omitempty"`
}

// LifecycleWrite is non-secret rotation metadata on create/update.
type LifecycleWrite struct {
	LastRotatedAt    *time.Time `json:"last_rotated_at,omitempty"`
	RotationInterval string     `json:"rotation_interval,omitempty"`
}

// OptionalSecret is a write-only secret ref. Omitted means retain.
// JSON null or an empty object clears the ref (rejected if the method stays enabled).
type OptionalSecret struct {
	Present     bool   `json:"-"`
	Clear       bool   `json:"-"`
	File        string `json:"file,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// UnmarshalJSON treats null as an explicit clear and a missing field as omit.
// Unknown keys are rejected so nested secret objects honor DisallowUnknownFields.
func (s *OptionalSecret) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		s.Present = true
		s.Clear = true
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var aux struct {
		File        string `json:"file"`
		Environment string `json:"environment"`
	}
	if err := dec.Decode(&aux); err != nil {
		return domain.NewError(domain.CodeInvalidArgument, "invalid request body")
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return domain.NewError(domain.CodeInvalidArgument, "invalid request body")
	}
	s.Present = true
	s.File = aux.File
	s.Environment = aux.Environment
	s.Clear = aux.File == "" && aux.Environment == ""
	return nil
}

// OptionalPolicyID is omit / set / JSON-null-clear for radius_policy_id.
type OptionalPolicyID struct {
	Present bool
	Clear   bool
	Value   string
}

// IsZero lets encoding/json omitempty skip an unset field.
func (p OptionalPolicyID) IsZero() bool { return !p.Present }

// UnmarshalJSON treats null and "" as an explicit clear.
func (p *OptionalPolicyID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		p.Present = true
		p.Clear = true
		p.Value = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return domain.NewError(domain.CodeInvalidArgument, "radius_policy_id must be a string or null")
	}
	p.Present = true
	p.Value = s
	p.Clear = s == ""
	return nil
}

// MarshalJSON emits null when cleared so REST/MCP parity stays exact.
func (p OptionalPolicyID) MarshalJSON() ([]byte, error) {
	if !p.Present || p.Clear {
		return []byte("null"), nil
	}
	return json.Marshal(p.Value)
}

func (p OptionalPolicyID) patch() *string {
	if !p.Present {
		return nil
	}
	s := p.Value
	if p.Clear {
		s = ""
	}
	return &s
}

package operations

import (
	"bytes"
	"encoding/json"
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
	ID           string             `json:"id"`
	DisplayName  *string            `json:"display_name,omitempty"`
	Enabled      *bool              `json:"enabled,omitempty"`
	Labels       *map[string]string `json:"labels,omitempty"`
	GroupIDs     *[]string          `json:"group_ids,omitempty"`
	Rules        *RuleSetView       `json:"rules,omitempty"`
	Login        OptionalSecret     `json:"login,omitempty"`
	Challenge    OptionalSecret     `json:"challenge,omitempty"`
	Enable       OptionalSecret     `json:"enable,omitempty"`
	Restrictions *RestrictionsView  `json:"restrictions,omitempty"`
	Override     bool               `json:"override,omitempty"`
}

// UpdateUserRequest is a typed user patch. Omitted fields are unchanged.
type UpdateUserRequest struct {
	ID           string             `json:"id"`
	DisplayName  *string            `json:"display_name,omitempty"`
	Enabled      *bool              `json:"enabled,omitempty"`
	Labels       *map[string]string `json:"labels,omitempty"`
	GroupIDs     *[]string          `json:"group_ids,omitempty"`
	Rules        *RuleSetView       `json:"rules,omitempty"`
	Login        OptionalSecret     `json:"login,omitempty"`
	Challenge    OptionalSecret     `json:"challenge,omitempty"`
	Enable       OptionalSecret     `json:"enable,omitempty"`
	Restrictions *RestrictionsView  `json:"restrictions,omitempty"`
}

// DeleteUserRequest deletes a runtime user or tombstones a baseline user.
type DeleteUserRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// User is the secret-free administrative view.
type User struct {
	ID                  string              `json:"id"`
	DisplayName         string              `json:"display_name,omitempty"`
	Enabled             bool                `json:"enabled"`
	Source              domain.ObjectSource `json:"source"`
	ShadowsSource       domain.ObjectSource `json:"shadows_source,omitempty"`
	Deleted             bool                `json:"deleted,omitempty"`
	RevisionCreated     domain.Revision     `json:"revision_created"`
	RevisionUpdated     domain.Revision     `json:"revision_updated"`
	EffectiveRevision   domain.Revision     `json:"effective_revision"`
	Labels              map[string]string   `json:"labels,omitempty"`
	GroupIDs            []string            `json:"group_ids,omitempty"`
	Rules               RuleSetView         `json:"rules"`
	Restrictions        RestrictionsView    `json:"restrictions"`
	ASCIIPapConfigured  bool                `json:"ascii_pap_configured"`
	ChallengeConfigured bool                `json:"challenge_configured"`
	EnableConfigured    bool                `json:"enable_configured"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

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
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

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
	ID                    string             `json:"id"`
	DisplayName           *string            `json:"display_name,omitempty"`
	Enabled               *bool              `json:"enabled,omitempty"`
	Priority              *int               `json:"priority,omitempty"`
	Labels                *map[string]string `json:"labels,omitempty"`
	Match                 *ClientMatchView   `json:"match,omitempty"`
	SharedSecret          OptionalSecret     `json:"shared_secret,omitempty"`
	SharedSecretLifecycle *LifecycleWrite    `json:"shared_secret_lifecycle,omitempty"`
	Authentication        *ClientAuthView    `json:"authentication,omitempty"`
	Authorization         *ClientAuthzView   `json:"authorization,omitempty"`
	Accounting            *ClientAcctView    `json:"accounting,omitempty"`
	Override              bool               `json:"override,omitempty"`
}

// UpdateClientRequest is a typed client patch.
type UpdateClientRequest struct {
	ID                    string             `json:"id"`
	DisplayName           *string            `json:"display_name,omitempty"`
	Enabled               *bool              `json:"enabled,omitempty"`
	Priority              *int               `json:"priority,omitempty"`
	Labels                *map[string]string `json:"labels,omitempty"`
	Match                 *ClientMatchView   `json:"match,omitempty"`
	SharedSecret          OptionalSecret     `json:"shared_secret,omitempty"`
	SharedSecretLifecycle *LifecycleWrite    `json:"shared_secret_lifecycle,omitempty"`
	Authentication        *ClientAuthView    `json:"authentication,omitempty"`
	Authorization         *ClientAuthzView   `json:"authorization,omitempty"`
	Accounting            *ClientAcctView    `json:"accounting,omitempty"`
}

// DeleteClientRequest deletes a runtime client or tombstones a baseline client.
type DeleteClientRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// Client is the secret-free administrative view.
type Client struct {
	ID                     string              `json:"id"`
	DisplayName            string              `json:"display_name,omitempty"`
	Enabled                bool                `json:"enabled"`
	Priority               int                 `json:"priority"`
	Source                 domain.ObjectSource `json:"source"`
	ShadowsSource          domain.ObjectSource `json:"shadows_source,omitempty"`
	Deleted                bool                `json:"deleted,omitempty"`
	RevisionCreated        domain.Revision     `json:"revision_created"`
	RevisionUpdated        domain.Revision     `json:"revision_updated"`
	EffectiveRevision      domain.Revision     `json:"effective_revision"`
	Labels                 map[string]string   `json:"labels,omitempty"`
	Match                  ClientMatchView     `json:"match"`
	SharedSecretConfigured bool                `json:"shared_secret_configured"`
	SharedSecretLifecycle  string              `json:"shared_secret_lifecycle"`
	Authentication         ClientAuthView      `json:"authentication"`
	Authorization          ClientAuthzView     `json:"authorization"`
	Accounting             ClientAcctView      `json:"accounting"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
}

// ClientList is clients.list output in id order.
type ClientList struct {
	Revision   domain.Revision `json:"revision"`
	Items      []Client        `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

func (c ClientList) envelopeRevision() domain.Revision { return c.Revision }

// RuleSetView is services + command_rules on the wire.
type RuleSetView struct {
	Services     []ServiceRuleView `json:"services,omitempty"`
	CommandRules []CommandRuleView `json:"command_rules,omitempty"`
}

// ServiceRuleView is one session/service rule. Action is permit_add, permit_replace, or deny.
type ServiceRuleView struct {
	Service         string          `json:"service"`
	Protocol        *string         `json:"protocol,omitempty"`
	Action          string          `json:"action"`
	ReplyAttributes []PolicyTraceAV `json:"reply_attributes,omitempty"`
}

// CommandRuleView is one command rule.
type CommandRuleView struct {
	ID        string    `json:"id"`
	Priority  int       `json:"priority"`
	Action    string    `json:"action"`
	Command   MatchView `json:"command"`
	Arguments MatchView `json:"arguments"`
	Reason    string    `json:"reason,omitempty"`
}

// MatchView is exactly one of exact or pattern.
type MatchView struct {
	Exact   string `json:"exact,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// RestrictionsView is client and time gates.
type RestrictionsView struct {
	ClientIDs   []string   `json:"client_ids,omitempty"`
	ValidAfter  *time.Time `json:"valid_after,omitempty"`
	ValidBefore *time.Time `json:"valid_before,omitempty"`
}

// ClientMatchView is identity selection input.
type ClientMatchView struct {
	SourceCIDRs []string      `json:"source_cidrs,omitempty"`
	Transports  []string      `json:"transports,omitempty"`
	Mode        string        `json:"mode,omitempty"`
	Certificate CertMatchView `json:"certificate"`
}

// CertMatchView is TLS SAN constraints.
type CertMatchView struct {
	DNSSANs []string `json:"dns_sans,omitempty"`
	IPSANs  []string `json:"ip_sans,omitempty"`
}

// ClientAuthView is per-client authentication policy.
type ClientAuthView struct {
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	DefaultService string   `json:"default_service,omitempty"`
}

// ClientAuthzView holds extra group membership appended after the user.
type ClientAuthzView struct {
	DefaultGroupIDs []string `json:"default_group_ids,omitempty"`
}

// ClientAcctView is per-client accounting acceptance.
type ClientAcctView struct {
	Enabled        bool `json:"enabled"`
	AcceptStart    bool `json:"accept_start"`
	AcceptStop     bool `json:"accept_stop"`
	AcceptWatchdog bool `json:"accept_watchdog"`
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
func (s *OptionalSecret) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		s.Present = true
		s.Clear = true
		return nil
	}
	var aux struct {
		File        string `json:"file"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	s.Present = true
	s.File = aux.File
	s.Environment = aux.Environment
	s.Clear = aux.File == "" && aux.Environment == ""
	return nil
}

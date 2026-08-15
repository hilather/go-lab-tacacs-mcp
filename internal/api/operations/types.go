package operations

import (
	"reflect"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Stable IDs of the handlers implemented in this package.
const (
	IDSystemStatusGet    = "system.status.get"
	IDSystemBuildGet     = "system.build.get"
	IDConfigEffectiveGet = "config.effective.get"
	IDConfigValidate     = "config.validate"
	IDConfigReload       = "config.reload"
	IDConfigExport       = "config.export"
	IDRuntimeReset       = "runtime.reset"
	IDUsersList          = "users.list"
	IDUsersGet           = "users.get"
	IDUsersCreate        = "users.create"
	IDUsersUpdate        = "users.update"
	IDUsersDelete        = "users.delete"
	IDGroupsList         = "groups.list"
	IDGroupsGet          = "groups.get"
	IDGroupsCreate       = "groups.create"
	IDGroupsUpdate       = "groups.update"
	IDGroupsDelete       = "groups.delete"
	IDClientsList        = "clients.list"
	IDClientsGet         = "clients.get"
	IDClientsCreate      = "clients.create"
	IDClientsUpdate      = "clients.update"
	IDClientsDelete      = "clients.delete"
	IDTokensList         = "tokens.list"
	IDTokensCreate       = "tokens.create"
	IDTokensRevoke       = "tokens.revoke"
	IDSessionCreate      = "session.create"
	IDSessionDelete      = "session.delete"
	IDPolicyEvaluate     = "policy.evaluate"
	IDAuthenticationTest = "authentication.test"
	IDEventsList         = "events.list"
	IDEventsSubscribe    = "events.subscribe"
)

// Specification versions reported by system.build.get.
const (
	MCPSpecification  = "2026-07-28"
	TACACSConformance = "RFC 8907; RFC 9887"
)

// Listener IDs match configuration keys and runtime inventory IDs.
const (
	ListenerLegacy           = "legacy_tacacs"
	ListenerSecure           = "secure_tacacs"
	ListenerHTTP             = "http"
	ListenerRADIUSAccess     = "radius_access"
	ListenerRADIUSAccounting = "radius_accounting"
)

// TransportHTTP is the admin listener. TACACS transports use domain.Transport.
const TransportHTTP = "http"

// TransportUDP is the RADIUS listener status string. It is not a domain.Transport.
const TransportUDP = "udp"

// Per-protocol conformance_status values reported by system.build.get.
const (
	ConformanceStatusPass    = "pass"
	ConformanceStatusPartial = "partial"
)

// ColocatedTopologyWarning is the non-secret notice required when both TACACS
// listeners are enabled.
const ColocatedTopologyWarning = "Both legacy TACACS+ and secure TACACS+ listeners are enabled. This is a co-located lab topology; TLS-only is the preferred production-like profile."

// GetStatusRequest is the empty input for system.status.get.
type GetStatusRequest struct{}

// ListenerStatus is configured listener identity plus live Runtime stats.
// TACACS transport stays legacy/tls. RADIUS uses udp (not a domain.Transport).
type ListenerStatus struct {
	ID             string   `json:"id"`
	Enabled        bool     `json:"enabled"`
	Bind           string   `json:"bind"`
	AdvertisedPort int      `json:"advertised_port,omitempty"`
	Transport      string   `json:"transport"`
	Protocol       string   `json:"protocol"`
	Carrier        string   `json:"carrier"`
	Roles          []string `json:"roles"`
	Ready          bool     `json:"ready"`
	Required       bool     `json:"required"`
	Inflight       int      `json:"inflight"`
	QueueDepth     int      `json:"queue_depth"`
	LastErrorCode  string   `json:"last_error_code,omitempty"`
}

// Status is the system.status.get result. It contains no secret material.
type Status struct {
	InstanceID        string           `json:"instance_id"`
	Revision          domain.Revision  `json:"revision"`
	BaselineHash      string           `json:"baseline_hash"`
	OverlayHash       string           `json:"overlay_hash"`
	CompiledAt        time.Time        `json:"compiled_at"`
	Listeners         []ListenerStatus `json:"listeners"`
	ColocatedTopology bool             `json:"colocated_topology"`
	TopologyWarning   string           `json:"topology_warning,omitempty"`
	Users             int              `json:"users"`
	Groups            int              `json:"groups"`
	Clients           int              `json:"clients"`
	Tokens            int              `json:"tokens"`
	Warnings          []string         `json:"warnings,omitempty"`
}

// GetBuildRequest is the empty input for system.build.get.
type GetBuildRequest struct{}

// BuildInfo is the system.build.get result. Paths and secrets are omitted.
type BuildInfo struct {
	Version           string                         `json:"version"`
	Commit            string                         `json:"commit"`
	BuildTime         string                         `json:"build_time"`
	GoVersion         string                         `json:"go_version"`
	UIVersion         string                         `json:"ui_version"`
	SchemaVersion     int                            `json:"schema_version"`
	TACACSConformance string                         `json:"tacacs_conformance"`
	MCPSpecification  string                         `json:"mcp_specification"`
	Protocols         map[string]ProtocolConformance `json:"protocols"`
}

// ProtocolConformance is one protocols map entry on system.build.get.
// RADIUS stays partial until MVP conformance rows have evidence.
type ProtocolConformance struct {
	Standards         []string `json:"standards"`
	ConformanceStatus string   `json:"conformance_status"`
}

// EvaluatePolicyRequest is the policy.evaluate input. Arguments replay a
// live AUTHOR AV list so explain uses the same evaluator as the wire path.
type EvaluatePolicyRequest struct {
	UserID        string          `json:"user_id"`
	ClientID      string          `json:"client_id,omitempty"`
	Service       string          `json:"service"`
	Protocol      string          `json:"protocol,omitempty"`
	Cmd           string          `json:"cmd,omitempty"`
	CmdArgs       []string        `json:"cmd_args,omitempty"`
	Arguments     []PolicyTraceAV `json:"arguments,omitempty"`
	AuthenMethod  string          `json:"authen_method,omitempty"`
	AuthenType    string          `json:"authen_type,omitempty"`
	AuthenService string          `json:"authen_service,omitempty"`
	Privilege     uint8           `json:"privilege,omitempty"`
	Port          string          `json:"port,omitempty"`
	Remote        string          `json:"remote,omitempty"`
}

// PolicyTrace is the redacted explanation returned by policy.evaluate.
type PolicyTrace struct {
	Evaluator         string             `json:"evaluator"`
	UserID            string             `json:"user_id"`
	ClientID          string             `json:"client_id"`
	Service           string             `json:"service"`
	Protocol          string             `json:"protocol"`
	Cmd               string             `json:"cmd"`
	CmdArgs           []string           `json:"cmd_args"`
	DisplayCmd        string             `json:"display_cmd"`
	RequestArguments  []PolicyTraceAV    `json:"request_arguments"`
	AuthenMethod      string             `json:"authen_method"`
	AuthenType        string             `json:"authen_type,omitempty"`
	AuthenService     string             `json:"authen_service,omitempty"`
	Privilege         uint8              `json:"privilege"`
	Port              string             `json:"port,omitempty"`
	Remote            string             `json:"remote,omitempty"`
	EffectiveGroupIDs []string           `json:"effective_group_ids"`
	Steps             []PolicyTraceStep  `json:"steps"`
	Winner            *PolicyTraceWinner `json:"winner"`
	Decision          string             `json:"decision"`
	Status            string             `json:"status"`
	Arguments         []PolicyTraceAV    `json:"arguments"`
	DefaultDeny       string             `json:"default_deny,omitempty"`
	Error             string             `json:"error,omitempty"`
}

// PolicyTraceStep is one considered rule.
type PolicyTraceStep struct {
	Source  string `json:"source"`
	RuleID  string `json:"rule_id"`
	Kind    string `json:"kind"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

// PolicyTraceWinner names the first matching rule.
type PolicyTraceWinner struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
}

// PolicyTraceAV is a stable AV encoding.
type PolicyTraceAV struct {
	Name      string `json:"name" yaml:"name"`
	Separator string `json:"separator" yaml:"separator"`
	Value     string `json:"value" yaml:"value"`
}

// ListEventsRequest is the events.list cursor page. Optional Protocol,
// ListenerRole, PacketCode, and Outcome AND with Categories.
type ListEventsRequest struct {
	Cursor       string   `json:"cursor,omitempty"`
	Limit        int      `json:"limit,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	ListenerRole string   `json:"listener_role,omitempty"`
	PacketCode   string   `json:"packet_code,omitempty"`
	Outcome      string   `json:"outcome,omitempty"`
}

// EventList is one redacted page from the ring.
type EventList struct {
	Items       []EventView `json:"items"`
	NextCursor  *string     `json:"next_cursor"`
	Reset       bool        `json:"reset"`
	Overwritten uint64      `json:"overwritten"`
}

// EventView is the adapter-facing event body.
type EventView struct {
	SchemaVersion int             `json:"schema_version"`
	ID            uint64          `json:"id"`
	Time          time.Time       `json:"time"`
	Category      string          `json:"category"`
	Type          string          `json:"type"`
	Result        string          `json:"result"`
	Transport     string          `json:"transport,omitempty"`
	ClientID      string          `json:"client_id,omitempty"`
	SessionID     uint32          `json:"session_id,omitempty"`
	Revision      domain.Revision `json:"revision,omitempty"`
	UserID        string          `json:"user_id,omitempty"`
	Command       string          `json:"command,omitempty"`
	TaskID        string          `json:"task_id,omitempty"`
	Arguments     []EventAV       `json:"arguments,omitempty"`
	StartTime     *time.Time      `json:"start_time,omitempty"`
	StopTime      *time.Time      `json:"stop_time,omitempty"`
	AuthenMethod  string          `json:"authen_method,omitempty"`
	AuthenType    string          `json:"authen_type,omitempty"`
	Service       string          `json:"service,omitempty"`
	Privilege     uint8           `json:"privilege"`
	Port          string          `json:"port,omitempty"`
	Remote        string          `json:"remote,omitempty"`
	Protocol      string          `json:"protocol,omitempty"`
	Carrier       string          `json:"carrier,omitempty"`
	ListenerRole  string          `json:"listener_role,omitempty"`
	ListenerID    string          `json:"listener_id,omitempty"`
	PacketCode    string          `json:"packet_code,omitempty"`
	Outcome       string          `json:"outcome,omitempty"`
	ReasonCode    string          `json:"reason_code,omitempty"`
	EndpointID    string          `json:"endpoint_id,omitempty"`
	AcctSessionID string          `json:"acct_session_id,omitempty"`
}

// EventAV is one stored attribute-value pair.
type EventAV struct {
	Name      string `json:"name"`
	Separator string `json:"separator"`
	Value     string `json:"value"`
}

type (
	SubscribeEventsRequest  struct{}
	EventStream             struct{}
	HealthRequest           struct{}
	HealthResult            struct{}
	GetOpenAPIRequest       struct{}
	OpenAPIDocument         struct{}
	MCPDiscoverRequest      struct{}
	MCPDiscoverResult       struct{}
	MCPToolsListRequest     struct{}
	MCPToolsListResult      struct{}
	MCPResourcesListRequest struct{}
	MCPResourcesListResult  struct{}
	MCPListChangedRequest   struct{}
	MCPNotification         struct{}
)

// DeleteResult is the response for delete/revoke operations.
type DeleteResult struct {
	ID       string          `json:"id,omitempty"`
	Revision domain.Revision `json:"revision,omitempty"`
}

func (d DeleteResult) envelopeRevision() domain.Revision { return d.Revision }

func defaultCatalog() map[string]reflect.Type {
	values := []any{
		GetStatusRequest{}, Status{},
		GetBuildRequest{}, BuildInfo{}, ProtocolConformance{},
		GetEffectiveConfigRequest{}, EffectiveConfig{},
		ValidateConfigRequest{}, ValidateConfigResult{},
		ReloadConfigRequest{}, ReloadConfigResult{},
		ExportConfigRequest{}, ExportConfigResult{},
		ResetRuntimeRequest{}, ResetRuntimeResult{},
		ListUsersRequest{}, GetUserRequest{}, CreateUserRequest{}, UpdateUserRequest{}, DeleteUserRequest{},
		UserList{}, User{}, DeleteResult{},
		ListGroupsRequest{}, GetGroupRequest{}, CreateGroupRequest{}, UpdateGroupRequest{}, DeleteGroupRequest{},
		GroupList{}, Group{},
		ListClientsRequest{}, GetClientRequest{}, CreateClientRequest{}, UpdateClientRequest{}, DeleteClientRequest{},
		ClientList{}, Client{}, ClientProtocolsView{}, ClientRADIUSWrite{}, ClientEndpointWrite{}, ClientEndpointView{},
		ListTokensRequest{}, CreateTokenRequest{}, RevokeTokenRequest{},
		TokenList{}, CreatedToken{},
		EvaluatePolicyRequest{}, PolicyTrace{},
		TestAuthenticationRequest{}, AuthenticationTestResult{},
		ListEventsRequest{}, EventList{},
		SubscribeEventsRequest{}, EventStream{},
		HealthRequest{}, HealthResult{},
		GetOpenAPIRequest{}, OpenAPIDocument{},
		CreateSessionRequest{}, Session{}, DeleteSessionRequest{},
		MCPDiscoverRequest{}, MCPDiscoverResult{},
		MCPToolsListRequest{}, MCPToolsListResult{},
		MCPResourcesListRequest{}, MCPResourcesListResult{},
		MCPListChangedRequest{}, MCPNotification{},
	}
	out := make(map[string]reflect.Type, len(values))
	for _, v := range values {
		t := reflect.TypeOf(v)
		out[t.Name()] = t
	}
	return out
}

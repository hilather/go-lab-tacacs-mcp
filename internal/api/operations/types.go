package operations

import (
	"reflect"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Stable IDs of the handlers implemented in this package.
const (
	IDSystemStatusGet = "system.status.get"
	IDSystemBuildGet  = "system.build.get"
)

// Specification versions reported by system.build.get.
const (
	MCPSpecification  = "2026-07-28"
	TACACSConformance = "RFC 8907; RFC 9887"
)

// Listener IDs match configuration keys.
const (
	ListenerLegacy = "legacy_tacacs"
	ListenerSecure = "secure_tacacs"
	ListenerHTTP   = "http"
)

// TransportHTTP is the admin listener. TACACS transports use domain.Transport.
const TransportHTTP = "http"

// ColocatedTopologyWarning is the non-secret notice required when both TACACS
// listeners are enabled.
const ColocatedTopologyWarning = "Both legacy TACACS+ and secure TACACS+ listeners are enabled. This is a co-located lab topology; TLS-only is the preferred production-like profile."

// GetStatusRequest is the empty input for system.status.get.
type GetStatusRequest struct{}

// ListenerStatus is configured listener identity from the published snapshot.
// Live bind/accept counts are not part of this skeleton.
type ListenerStatus struct {
	ID             string `json:"id"`
	Enabled        bool   `json:"enabled"`
	Bind           string `json:"bind"`
	AdvertisedPort int    `json:"advertised_port,omitempty"`
	Transport      string `json:"transport"`
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
	Version           string `json:"version"`
	Commit            string `json:"commit"`
	BuildTime         string `json:"build_time"`
	GoVersion         string `json:"go_version"`
	UIVersion         string `json:"ui_version"`
	SchemaVersion     int    `json:"schema_version"`
	TACACSConformance string `json:"tacacs_conformance"`
	MCPSpecification  string `json:"mcp_specification"`
}

// Stub request and response types named to match api/operations.yaml.
// Fields are added when those handlers are implemented.
type (
	GetEffectiveConfigRequest struct{}
	EffectiveConfig           struct{}
	ValidateConfigRequest     struct{}
	ValidateConfigResult      struct{}
	ReloadConfigRequest       struct{}
	ReloadConfigResult        struct{}
	ExportConfigRequest       struct{}
	ExportConfigResult        struct{}
	ResetRuntimeRequest       struct{}
	ResetRuntimeResult        struct{}
	ListUsersRequest          struct{}
	GetUserRequest            struct{}
	CreateUserRequest         struct{}
	UpdateUserRequest         struct{}
	DeleteUserRequest         struct{}
	UserList                  struct{}
	User                      struct{}
	DeleteResult              struct{}
	ListGroupsRequest         struct{}
	GetGroupRequest           struct{}
	CreateGroupRequest        struct{}
	UpdateGroupRequest        struct{}
	DeleteGroupRequest        struct{}
	GroupList                 struct{}
	Group                     struct{}
	ListClientsRequest        struct{}
	GetClientRequest          struct{}
	CreateClientRequest       struct{}
	UpdateClientRequest       struct{}
	DeleteClientRequest       struct{}
	ClientList                struct{}
	Client                    struct{}
	ListTokensRequest         struct{}
	CreateTokenRequest        struct{}
	RevokeTokenRequest        struct{}
	TokenList                 struct{}
	CreatedToken              struct{}
	EvaluatePolicyRequest     struct{}
	PolicyTrace               struct{}
	TestAuthenticationRequest struct{}
	AuthenticationTestResult  struct{}
	ListEventsRequest         struct{}
	EventList                 struct{}
	SubscribeEventsRequest    struct{}
	EventStream               struct{}
	HealthRequest             struct{}
	HealthResult              struct{}
	GetOpenAPIRequest         struct{}
	OpenAPIDocument           struct{}
	CreateSessionRequest      struct{}
	Session                   struct{}
	DeleteSessionRequest      struct{}
	MCPDiscoverRequest        struct{}
	MCPDiscoverResult         struct{}
	MCPToolsListRequest       struct{}
	MCPToolsListResult        struct{}
	MCPResourcesListRequest   struct{}
	MCPResourcesListResult    struct{}
	MCPListChangedRequest     struct{}
	MCPNotification           struct{}
)

func defaultCatalog() map[string]reflect.Type {
	values := []any{
		GetStatusRequest{}, Status{},
		GetBuildRequest{}, BuildInfo{},
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
		ClientList{}, Client{},
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

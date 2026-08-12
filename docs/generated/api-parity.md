# Generated REST/MCP operation inventory

Do not hand-edit this file. Run `make generate`.

Source: `api/operations.yaml`

| Operation ID | Description | Disposition | Scopes | REST | MCP | Request | Response | Mutating | Idempotent | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| system.status.get | Read listener and snapshot status | PARITY_REQUIRED | state:read | GET /api/v1/status | tool taclab.system.status.get taclab://status | GetStatusRequest | Status | false | true | NOT_STARTED |
| system.build.get | Read build and specification versions | PARITY_REQUIRED | state:read | GET /api/v1/build | tool taclab.system.build.get taclab://build | GetBuildRequest | BuildInfo | false | true | NOT_STARTED |
| config.effective.get | Read the redacted effective configuration | PARITY_REQUIRED | state:read | GET /api/v1/config/effective | tool taclab.config.effective.get taclab://config/effective | GetEffectiveConfigRequest | EffectiveConfig | false | true | NOT_STARTED |
| config.validate | Validate a candidate configuration without publishing state | PARITY_REQUIRED | state:write | POST /api/v1/config/validate | tool taclab.config.validate | ValidateConfigRequest | ValidateConfigResult | false | true | NOT_STARTED |
| config.reload | Reload the mounted baseline and rebase the overlay | PARITY_REQUIRED | config:reload | POST /api/v1/config/reload | tool taclab.config.reload | ReloadConfigRequest | ReloadConfigResult | true | conditional | NOT_STARTED |
| config.export | Export a redacted effective configuration document | PARITY_REQUIRED | config:export | GET /api/v1/config/export | tool taclab.config.export | ExportConfigRequest | ExportConfigResult | false | true | NOT_STARTED |
| runtime.reset | Drop the entire runtime overlay including tombstones | PARITY_REQUIRED | runtime:reset | POST /api/v1/runtime/reset | tool taclab.runtime.reset | ResetRuntimeRequest | ResetRuntimeResult | true | conditional | NOT_STARTED |
| users.list | List users in deterministic id order | PARITY_REQUIRED | state:read | GET /api/v1/users | tool taclab.users.list taclab://users | ListUsersRequest | UserList | false | true | NOT_STARTED |
| users.get | Get one user by id | PARITY_REQUIRED | state:read | GET /api/v1/users/{id} | tool taclab.users.get | GetUserRequest | User | false | true | NOT_STARTED |
| users.create | Create a runtime user or override a baseline user | PARITY_REQUIRED | state:write | POST /api/v1/users | tool taclab.users.create | CreateUserRequest | User | true | conditional | NOT_STARTED |
| users.update | Apply a typed patch to a user | PARITY_REQUIRED | state:write | PATCH /api/v1/users/{id} | tool taclab.users.update | UpdateUserRequest | User | true | conditional | NOT_STARTED |
| users.delete | Delete a runtime user or tombstone a baseline user | PARITY_REQUIRED | state:write | DELETE /api/v1/users/{id} | tool taclab.users.delete | DeleteUserRequest | DeleteResult | true | true | NOT_STARTED |
| groups.list | List groups in deterministic id order | PARITY_REQUIRED | state:read | GET /api/v1/groups | tool taclab.groups.list taclab://groups | ListGroupsRequest | GroupList | false | true | NOT_STARTED |
| groups.get | Get one group by id | PARITY_REQUIRED | state:read | GET /api/v1/groups/{id} | tool taclab.groups.get | GetGroupRequest | Group | false | true | NOT_STARTED |
| groups.create | Create a runtime group or override a baseline group | PARITY_REQUIRED | state:write | POST /api/v1/groups | tool taclab.groups.create | CreateGroupRequest | Group | true | conditional | NOT_STARTED |
| groups.update | Apply a typed patch to a group | PARITY_REQUIRED | state:write | PATCH /api/v1/groups/{id} | tool taclab.groups.update | UpdateGroupRequest | Group | true | conditional | NOT_STARTED |
| groups.delete | Delete a runtime group or tombstone a baseline group | PARITY_REQUIRED | state:write | DELETE /api/v1/groups/{id} | tool taclab.groups.delete | DeleteGroupRequest | DeleteResult | true | true | NOT_STARTED |
| clients.list | List TACACS clients in deterministic id order | PARITY_REQUIRED | state:read | GET /api/v1/clients | tool taclab.clients.list taclab://clients | ListClientsRequest | ClientList | false | true | NOT_STARTED |
| clients.get | Get one client by id | PARITY_REQUIRED | state:read | GET /api/v1/clients/{id} | tool taclab.clients.get | GetClientRequest | Client | false | true | NOT_STARTED |
| clients.create | Create a runtime client or override a baseline client | PARITY_REQUIRED | state:write | POST /api/v1/clients | tool taclab.clients.create | CreateClientRequest | Client | true | conditional | NOT_STARTED |
| clients.update | Apply a typed patch to a client | PARITY_REQUIRED | state:write | PATCH /api/v1/clients/{id} | tool taclab.clients.update | UpdateClientRequest | Client | true | conditional | NOT_STARTED |
| clients.delete | Delete a runtime client or tombstone a baseline client | PARITY_REQUIRED | state:write | DELETE /api/v1/clients/{id} | tool taclab.clients.delete | DeleteClientRequest | DeleteResult | true | true | NOT_STARTED |
| tokens.list | List API tokens without secret values | PARITY_REQUIRED | tokens:manage | GET /api/v1/tokens | tool taclab.tokens.list | ListTokensRequest | TokenList | false | true | NOT_STARTED |
| tokens.create | Create an API token and return its value once | PARITY_REQUIRED | tokens:manage | POST /api/v1/tokens | tool taclab.tokens.create | CreateTokenRequest | CreatedToken | true | conditional | NOT_STARTED |
| tokens.revoke | Revoke an API token | PARITY_REQUIRED | tokens:manage | DELETE /api/v1/tokens/{id} | tool taclab.tokens.revoke | RevokeTokenRequest | DeleteResult | true | true | NOT_STARTED |
| policy.evaluate | Explain an authorization decision against the current snapshot | PARITY_REQUIRED | policy:test | POST /api/v1/policy/evaluate | tool taclab.policy.evaluate | EvaluatePolicyRequest | PolicyTrace | false | true | NOT_STARTED |
| authentication.test | Run an authentication test against the current snapshot | PARITY_REQUIRED | policy:test | POST /api/v1/authentication/test | tool taclab.authentication.test | TestAuthenticationRequest | AuthenticationTestResult | false | true | NOT_STARTED |
| events.list | Read a cursor page of redacted events from the ring | PARITY_REQUIRED | events:read | GET /api/v1/events | tool taclab.events.list taclab://events/recent | ListEventsRequest | EventList | false | true | NOT_STARTED |
| events.subscribe | Live event delivery. REST streams redacted bodies over SSE. MCP subscriptions/listen notifies taclab://events/recent with URI only; the client pulls bodies through events.list. | PARITY_DIFFERENT_BINDING | events:read | GET /api/v1/events/stream | listen subscriptions/listen taclab://events/recent pull events.list | SubscribeEventsRequest | EventStream | false | false | NOT_STARTED |
| health.live | Process liveness probe | REST_ONLY_PROTOCOL |  | GET /health/live |  | HealthRequest | HealthResult | false | true | NOT_STARTED |
| health.ready | Readiness probe | REST_ONLY_PROTOCOL |  | GET /health/ready |  | HealthRequest | HealthResult | false | true | NOT_STARTED |
| openapi.get | Serve the OpenAPI document | REST_ONLY_PROTOCOL |  | GET /api/openapi.json |  | GetOpenAPIRequest | OpenAPIDocument | false | true | NOT_STARTED |
| session.create | Exchange a bearer token for an HttpOnly UI session cookie | REST_ONLY_PROTOCOL |  | POST /api/v1/session |  | CreateSessionRequest | Session | true | false | NOT_STARTED |
| session.delete | End the UI session | REST_ONLY_PROTOCOL |  | DELETE /api/v1/session |  | DeleteSessionRequest | DeleteResult | true | true | NOT_STARTED |
| mcp.discover | MCP server/discover | MCP_ONLY_PROTOCOL |  |  | protocol server/discover | MCPDiscoverRequest | MCPDiscoverResult | false | true | NOT_STARTED |
| mcp.tools.list | MCP tools/list filtered by caller scopes | MCP_ONLY_PROTOCOL |  |  | protocol tools/list | MCPToolsListRequest | MCPToolsListResult | false | true | NOT_STARTED |
| mcp.resources.list | MCP resources/list filtered by caller scopes | MCP_ONLY_PROTOCOL |  |  | protocol resources/list | MCPResourcesListRequest | MCPResourcesListResult | false | true | NOT_STARTED |
| mcp.notifications.list_changed | MCP tools/list_changed and resources/list_changed notifications | MCP_ONLY_PROTOCOL |  |  | protocol notifications/list_changed | MCPListChangedRequest | MCPNotification | false | false | NOT_STARTED |


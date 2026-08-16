package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

const (
	openAPIVersion = "3.1.0"
	openAPITitle   = "TacLab REST API"
)

// OpenAPIPath is the checked-in OpenAPI document.
const OpenAPIPath = "api/openapi.json"

// TSTypesPath is the generated TypeScript types for the frozen surface.
const TSTypesPath = "web/src/generated/api.ts"

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	doc := BuildOpenAPI(s.Registry)
	raw, err := marshalStable(doc)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, domain.NewError(domain.CodeInternal, "cannot encode OpenAPI"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte("\n"))
}

// BuildOpenAPI returns the OpenAPI 3.1 document for the frozen REST set.
func BuildOpenAPI(reg *operations.Registry) map[string]any {
	schemas := map[string]any{}
	addProblemSchema(schemas)
	addEnvelopeSchema(schemas)
	addHealthSchema(schemas)
	for _, sample := range frozenSchemaTypes() {
		_ = schemaOf(reflect.TypeOf(sample), schemas)
	}

	paths := map[string]any{
		"/health/live":                   getPath("health.live", "Liveness probe", nil, refSchema("HealthStatus"), false),
		"/health/ready":                  getPath("health.ready", "Readiness probe", nil, refSchema("HealthStatus"), false),
		"/api/openapi.json":              getPath("openapi.get", "OpenAPI document", nil, map[string]any{"type": "object"}, false),
		"/api/v1/status":                 getPath(operations.IDSystemStatusGet, "Listener and snapshot status", []string{"state:read"}, envelopeRef("Status"), true),
		"/api/v1/build":                  getPath(operations.IDSystemBuildGet, "Build and specification versions", []string{"state:read"}, envelopeRef("BuildInfo"), true),
		"/api/v1/config/effective":       effectiveConfigPath(),
		"/api/v1/config/validate":        postPath(operations.IDConfigValidate, "Validate a candidate configuration without publishing", []string{"state:write"}, refSchema("ValidateConfigRequest"), envelopeRef("ValidateConfigResult"), false),
		"/api/v1/config/reload":          mutatingPostPath(operations.IDConfigReload, "Reload the mounted baseline", []string{"config:reload"}, refSchema("ReloadConfigRequest"), envelopeRef("ReloadConfigResult")),
		"/api/v1/config/export":          exportConfigPath(),
		"/api/v1/runtime/reset":          mutatingPostPath(operations.IDRuntimeReset, "Drop the runtime overlay including tombstones", []string{"runtime:reset"}, refSchema("ResetRuntimeRequest"), envelopeRef("ResetRuntimeResult")),
		"/api/v1/users":                  collectionPath(operations.IDUsersList, operations.IDUsersCreate, "users", "state:read", "state:write", "UserList", "CreateUserRequest", "User"),
		"/api/v1/users/{id}":             itemPath(operations.IDUsersGet, operations.IDUsersUpdate, operations.IDUsersDelete, "user", "state:read", "state:write", "User", "UpdateUserRequest"),
		"/api/v1/groups":                 collectionPath(operations.IDGroupsList, operations.IDGroupsCreate, "groups", "state:read", "state:write", "GroupList", "CreateGroupRequest", "Group"),
		"/api/v1/groups/{id}":            itemPath(operations.IDGroupsGet, operations.IDGroupsUpdate, operations.IDGroupsDelete, "group", "state:read", "state:write", "Group", "UpdateGroupRequest"),
		"/api/v1/clients":                collectionPath(operations.IDClientsList, operations.IDClientsCreate, "clients", "state:read", "state:write", "ClientList", "CreateClientRequest", "Client"),
		"/api/v1/clients/{id}":           itemPath(operations.IDClientsGet, operations.IDClientsUpdate, operations.IDClientsDelete, "client", "state:read", "state:write", "Client", "UpdateClientRequest"),
		"/api/v1/policy/evaluate":        postPath(operations.IDPolicyEvaluate, "Explain an authorization decision", []string{"policy:test"}, refSchema("EvaluatePolicyRequest"), envelopeRef("PolicyTrace"), false),
		"/api/v1/authentication/test":    postPath(operations.IDAuthenticationTest, "Run an authentication test against the current snapshot", []string{"policy:test"}, refSchema("TestAuthenticationRequest"), envelopeRef("AuthenticationTestResult"), false),
		"/api/v1/radius/access:test":     postPath(operations.IDRadiusAccessTest, "Simulate a RADIUS Access-Request without UDP", []string{"policy:test"}, refSchema("RadiusAccessTestRequest"), envelopeRef("RadiusAccessTestResult"), false),
		"/api/v1/radius/policy:evaluate": postPath(operations.IDRadiusPolicyEvaluate, "Explain a RADIUS access-policy decision", []string{"policy:test"}, refSchema("RadiusPolicyEvaluateRequest"), envelopeRef("RadiusPolicyEvaluateResult"), false),
		"/api/v1/radius/attributes":      getPath(operations.IDRadiusAttributesList, "List built-in RADIUS dictionary metadata", []string{"state:read"}, envelopeRef("RadiusAttributeList"), true),
		"/api/v1/events":                 listEventsPath(),
		"/api/v1/events/stream":          streamPath(),
		"/api/v1/tokens":                 tokensCollectionPath(),
		"/api/v1/tokens/{id}":            tokensItemPath(),
		"/api/v1/session":                sessionPath(),
	}

	_ = reg

	return map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{
			"title":       openAPITitle,
			"version":     "0.16.0",
			"description": "TacLab REST API. CSRF is required on cookie-authenticated mutations. cookie_secure follows listeners.http.tls.enabled.",
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":   "http",
					"scheme": "bearer",
				},
				"cookieAuth": map[string]any{
					"type": "apiKey",
					"in":   "cookie",
					"name": "taclab_session",
				},
			},
		},
	}
}

// WriteGenerated writes api/openapi.json and web/src/generated/api.ts.
func WriteGenerated(root string) error {
	if _, err := os.Stat(filepath.Join(root, "api", "operations.yaml")); err != nil {
		return nil
	}
	reg, err := operations.NewFromRepo(root, operations.Deps{})
	if err != nil {
		return err
	}
	doc := BuildOpenAPI(reg)
	raw, err := marshalStable(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "api"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, OpenAPIPath), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	ts := generateTS()
	dir := filepath.Join(root, "web", "src", "generated")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, TSTypesPath), []byte(ts), 0o644)
}

func frozenSchemaTypes() []any {
	return []any{
		operations.Status{},
		operations.ListenerStatus{},
		operations.BuildInfo{},
		operations.EvaluatePolicyRequest{},
		operations.PolicyTrace{},
		operations.PolicyTraceStep{},
		operations.PolicyTraceWinner{},
		operations.PolicyTraceAV{},
		operations.ListEventsRequest{},
		operations.EventList{},
		operations.EventView{},
		operations.EventAV{},
		operations.ListTokensRequest{},
		operations.CreateTokenRequest{},
		operations.RevokeTokenRequest{},
		operations.TokenView{},
		operations.TokenList{},
		operations.CreatedToken{},
		operations.Session{},
		operations.CreateSessionRequest{},
		operations.DeleteSessionRequest{},
		operations.DeleteResult{},
		operations.GetEffectiveConfigRequest{},
		operations.EffectiveConfig{},
		operations.ValidateConfigRequest{},
		operations.ValidateConfigResult{},
		operations.ValidationIssue{},
		operations.ReloadConfigRequest{},
		operations.ReloadConfigResult{},
		operations.ExportConfigRequest{},
		operations.ExportConfigResult{},
		operations.ResetRuntimeRequest{},
		operations.ResetRuntimeResult{},
		operations.ListUsersRequest{},
		operations.GetUserRequest{},
		operations.CreateUserRequest{},
		operations.UpdateUserRequest{},
		operations.DeleteUserRequest{},
		operations.User{},
		operations.UserList{},
		operations.ListGroupsRequest{},
		operations.GetGroupRequest{},
		operations.CreateGroupRequest{},
		operations.UpdateGroupRequest{},
		operations.DeleteGroupRequest{},
		operations.Group{},
		operations.GroupList{},
		operations.ListClientsRequest{},
		operations.GetClientRequest{},
		operations.CreateClientRequest{},
		operations.UpdateClientRequest{},
		operations.DeleteClientRequest{},
		operations.Client{},
		operations.ClientList{},
		operations.RuleSetView{},
		operations.ServiceRuleView{},
		operations.CommandRuleView{},
		operations.MatchView{},
		operations.RestrictionsView{},
		operations.ClientMatchView{},
		operations.CertMatchView{},
		operations.ClientAuthView{},
		operations.ClientAuthzView{},
		operations.ClientAcctView{},
		operations.ClientProtocolsView{},
		operations.ClientTACACSProtocolView{},
		operations.ClientRADIUSProtocolView{},
		operations.ClientEndpointView{},
		operations.ClientTACACSEndpointView{},
		operations.ClientEndpointWrite{},
		operations.ClientTACACSEndpointWrite{},
		operations.ClientRADIUSWrite{},
		operations.LifecycleWrite{},
		operations.OptionalSecret{},
		operations.TestAuthenticationRequest{},
		operations.AuthenticationTestResult{},
		operations.RadiusAccessTestRequest{},
		operations.RadiusAccessTestResult{},
		operations.RadiusAuthMethod{},
		operations.RadiusAttributeValue{},
		operations.RadiusPolicyEvaluateRequest{},
		operations.RadiusPolicyEvaluateResult{},
		operations.RadiusPolicyTrace{},
		operations.RadiusPolicyTraceStep{},
		operations.RadiusPolicyTraceWinner{},
		operations.ListRadiusAttributesRequest{},
		operations.RadiusAttributeList{},
		operations.RadiusAttributeMetadata{},
	}
}

func addProblemSchema(schemas map[string]any) {
	schemas["ProblemDetails"] = map[string]any{
		"type":     "object",
		"required": []any{"type", "title", "status", "detail", "code"},
		"properties": map[string]any{
			"type":     map[string]any{"type": "string"},
			"title":    map[string]any{"type": "string"},
			"status":   map[string]any{"type": "integer"},
			"detail":   map[string]any{"type": "string"},
			"code":     map[string]any{"type": "string"},
			"path":     map[string]any{"type": "string"},
			"instance": map[string]any{"type": "string"},
		},
		"additionalProperties": false,
	}
}

func addEnvelopeSchema(schemas map[string]any) {
	schemas["Envelope"] = map[string]any{
		"type":     "object",
		"required": []any{"revision", "request_id", "data"},
		"properties": map[string]any{
			"revision":   map[string]any{"type": "integer"},
			"request_id": map[string]any{"type": "string"},
			"data":       map[string]any{},
		},
	}
}

func addHealthSchema(schemas map[string]any) {
	schemas["HealthStatus"] = map[string]any{
		"type":     "object",
		"required": []any{"status"},
		"properties": map[string]any{
			"status": map[string]any{"type": "string"},
		},
		"additionalProperties": false,
	}
}

func refSchema(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func envelopeRef(name string) map[string]any {
	return map[string]any{
		"allOf": []any{
			refSchema("Envelope"),
			map[string]any{
				"type": "object",
				"properties": map[string]any{
					"data": refSchema(name),
				},
			},
		},
	}
}

func problemResponse() map[string]any {
	return map[string]any{
		"description": "RFC 9457 problem details with TacLab code",
		"content": map[string]any{
			"application/problem+json": map[string]any{
				"schema": refSchema("ProblemDetails"),
			},
		},
	}
}

func jsonResponse(desc string, schema map[string]any) map[string]any {
	return map[string]any{
		"description": desc,
		"content": map[string]any{
			"application/json": map[string]any{"schema": schema},
		},
	}
}

func bearerSecurity() []any {
	return []any{map[string]any{"bearerAuth": []any{}}, map[string]any{"cookieAuth": []any{}}}
}

func getPath(id, desc string, scopes []string, schema map[string]any, secured bool) map[string]any {
	op := map[string]any{
		"operationId": id,
		"summary":     desc,
		"responses": map[string]any{
			"200": jsonResponse("OK", schema),
			"401": problemResponse(),
			"403": problemResponse(),
			"503": problemResponse(),
		},
	}
	if len(scopes) > 0 {
		op["description"] = "Scopes: " + strings.Join(scopes, ", ")
	}
	if secured {
		op["security"] = bearerSecurity()
	}
	return map[string]any{"get": op}
}

func postPath(id, desc string, scopes []string, req, resp map[string]any, csrf bool) map[string]any {
	op := map[string]any{
		"operationId": id,
		"summary":     desc,
		"security":    bearerSecurity(),
		"requestBody": map[string]any{
			"required": true,
			"content": map[string]any{
				"application/json": map[string]any{"schema": req},
			},
		},
		"responses": map[string]any{
			"200": jsonResponse("OK", resp),
			"400": problemResponse(),
			"401": problemResponse(),
			"403": problemResponse(),
			"412": problemResponse(),
			"503": problemResponse(),
		},
	}
	if len(scopes) > 0 {
		op["description"] = "Scopes: " + strings.Join(scopes, ", ")
	}
	if csrf {
		op["parameters"] = []any{csrfParam()}
	}
	return map[string]any{"post": op}
}

func csrfParam() map[string]any {
	return map[string]any{
		"name":        "X-CSRF-Token",
		"in":          "header",
		"required":    false,
		"description": "Required on cookie-authenticated mutations.",
		"schema":      map[string]any{"type": "string"},
	}
}

func ifMatchParam() map[string]any {
	return map[string]any{
		"name":        "If-Match",
		"in":          "header",
		"required":    false,
		"description": `Optimistic concurrency. Format: "revision-N".`,
		"schema":      map[string]any{"type": "string"},
	}
}

func idempotencyParam() map[string]any {
	return map[string]any{
		"name":     "Idempotency-Key",
		"in":       "header",
		"required": false,
		"schema":   map[string]any{"type": "string"},
	}
}

func listEventsPath() map[string]any {
	op := getPath(operations.IDEventsList, "Cursor page of redacted events", []string{"events:read"}, envelopeRef("EventList"), true)
	get := op["get"].(map[string]any)
	get["parameters"] = []any{
		map[string]any{"name": "cursor", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer"}},
		map[string]any{"name": "category", "in": "query", "schema": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "style": "form", "explode": true},
		map[string]any{"name": "protocol", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "listener_role", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "packet_code", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "outcome", "in": "query", "schema": map[string]any{"type": "string"}},
	}
	return op
}

func streamPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"operationId": operations.IDEventsSubscribe,
			"summary":     "SSE stream of redacted event bodies",
			"description": "Clears the HTTP write deadline and emits comment keep-alives. Last-Event-ID resumes from the ring. Invalid Last-Event-ID is 400. A slow subscriber receives event: reset and the stream ends. Scopes: events:read. Does not consume the short-request in-flight cap.",
			"security":    bearerSecurity(),
			"parameters": []any{
				map[string]any{"name": "Last-Event-ID", "in": "header", "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "category", "in": "query", "schema": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "style": "form", "explode": true},
				map[string]any{"name": "protocol", "in": "query", "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "listener_role", "in": "query", "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "packet_code", "in": "query", "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "outcome", "in": "query", "schema": map[string]any{"type": "string"}},
			},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "text/event-stream",
					"content": map[string]any{
						"text/event-stream": map[string]any{
							"schema": map[string]any{"type": "string"},
						},
					},
				},
				"401": problemResponse(),
				"403": problemResponse(),
			},
		},
	}
}

func tokensCollectionPath() map[string]any {
	get := getPath(operations.IDTokensList, "List API tokens without secret values", []string{"tokens:manage"}, envelopeRef("TokenList"), true)
	getOp := get["get"].(map[string]any)
	getOp["parameters"] = []any{
		map[string]any{"name": "cursor", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer"}},
	}
	post := postPath(operations.IDTokensCreate, "Create an API token and return its value once", []string{"tokens:manage"}, refSchema("CreateTokenRequest"), envelopeRef("CreatedToken"), true)
	postOp := post["post"].(map[string]any)
	postOp["parameters"] = []any{csrfParam(), ifMatchParam(), idempotencyParam()}
	return map[string]any{"get": getOp, "post": postOp}
}

func tokensItemPath() map[string]any {
	return map[string]any{
		"delete": map[string]any{
			"operationId": operations.IDTokensRevoke,
			"summary":     "Revoke an API token",
			"description": "Scopes: tokens:manage",
			"security":    bearerSecurity(),
			"parameters": []any{
				map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
				map[string]any{"name": "tombstone", "in": "query", "schema": map[string]any{"type": "boolean"}},
				csrfParam(),
				ifMatchParam(),
			},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef("DeleteResult")),
				"401": problemResponse(),
				"403": problemResponse(),
				"404": problemResponse(),
				"412": problemResponse(),
			},
		},
	}
}

func viewParam() map[string]any {
	return map[string]any{"name": "view", "in": "query", "schema": map[string]any{"type": "string", "enum": []any{"effective", "baseline", "overlay"}}}
}

func listQueryParams() []any {
	return []any{
		map[string]any{"name": "cursor", "in": "query", "schema": map[string]any{"type": "string"}},
		map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer"}},
		map[string]any{"name": "include_deleted", "in": "query", "schema": map[string]any{"type": "boolean"}},
	}
}

func idParam() map[string]any {
	return map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}
}

func effectiveConfigPath() map[string]any {
	op := getPath(operations.IDConfigEffectiveGet, "Redacted effective configuration", []string{"state:read"}, envelopeRef("EffectiveConfig"), true)
	get := op["get"].(map[string]any)
	get["parameters"] = []any{viewParam()}
	return op
}

func exportConfigPath() map[string]any {
	op := getPath(operations.IDConfigExport, "Redacted configuration YAML", []string{"config:export"}, envelopeRef("ExportConfigResult"), true)
	get := op["get"].(map[string]any)
	get["parameters"] = []any{viewParam(), normalizeParam()}
	return op
}

func normalizeParam() map[string]any {
	return map[string]any{
		"name":        "normalize",
		"in":          "query",
		"description": "Explicit v1→v2 convert flag. Default false. A v1 source stays v1-shaped unless true.",
		"schema":      map[string]any{"type": "boolean", "default": false},
	}
}

func mutatingPostPath(id, desc string, scopes []string, req, resp map[string]any) map[string]any {
	op := postPath(id, desc, scopes, req, resp, true)
	post := op["post"].(map[string]any)
	post["parameters"] = []any{csrfParam(), ifMatchParam(), idempotencyParam()}
	post["requestBody"] = map[string]any{
		"required": false,
		"content": map[string]any{
			"application/json": map[string]any{"schema": req},
		},
	}
	return op
}

func collectionPath(listID, createID, name, readScope, writeScope, listSchema, createReq, createResp string) map[string]any {
	get := getPath(listID, "List "+name+" in deterministic id order", []string{readScope}, envelopeRef(listSchema), true)
	getOp := get["get"].(map[string]any)
	getOp["parameters"] = listQueryParams()
	post := postPath(createID, "Create a runtime "+name, []string{writeScope}, refSchema(createReq), envelopeRef(createResp), true)
	postOp := post["post"].(map[string]any)
	postOp["parameters"] = []any{csrfParam(), ifMatchParam(), idempotencyParam()}
	return map[string]any{"get": getOp, "post": postOp}
}

func itemPath(getID, updateID, deleteID, name, readScope, writeScope, getSchema, updateReq string) map[string]any {
	return map[string]any{
		"get": map[string]any{
			"operationId": getID,
			"summary":     "Get one " + name + " by id",
			"description": "Scopes: " + readScope,
			"security":    bearerSecurity(),
			"parameters": []any{
				idParam(),
				map[string]any{"name": "include_deleted", "in": "query", "schema": map[string]any{"type": "boolean"}},
			},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef(getSchema)),
				"401": problemResponse(),
				"403": problemResponse(),
				"404": problemResponse(),
			},
		},
		"patch": map[string]any{
			"operationId": updateID,
			"summary":     "Apply a typed patch to a " + name,
			"description": "Scopes: " + writeScope,
			"security":    bearerSecurity(),
			"parameters":  []any{idParam(), csrfParam(), ifMatchParam()},
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{"schema": refSchema(updateReq)},
				},
			},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef(getSchema)),
				"400": problemResponse(),
				"401": problemResponse(),
				"403": problemResponse(),
				"404": problemResponse(),
				"412": problemResponse(),
			},
		},
		"delete": map[string]any{
			"operationId": deleteID,
			"summary":     "Delete a runtime " + name + " or tombstone a baseline " + name,
			"description": "Scopes: " + writeScope,
			"security":    bearerSecurity(),
			"parameters": []any{
				idParam(),
				map[string]any{"name": "tombstone", "in": "query", "schema": map[string]any{"type": "boolean"}},
				csrfParam(),
				ifMatchParam(),
			},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef("DeleteResult")),
				"401": problemResponse(),
				"403": problemResponse(),
				"404": problemResponse(),
				"412": problemResponse(),
			},
		},
	}
}

func sessionPath() map[string]any {
	return map[string]any{
		"post": map[string]any{
			"operationId": operations.IDSessionCreate,
			"summary":     "Exchange a bearer token for an HttpOnly UI session cookie",
			"description": "REST_ONLY. CSRF is issued. cookie_secure follows HTTP TLS. Requires Authorization: Bearer.",
			"security":    []any{map[string]any{"bearerAuth": []any{}}},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef("Session")),
				"401": problemResponse(),
			},
		},
		"delete": map[string]any{
			"operationId": operations.IDSessionDelete,
			"summary":     "End the UI session",
			"description": "REST_ONLY. CSRF required for cookie auth.",
			"security":    []any{map[string]any{"cookieAuth": []any{}}},
			"parameters":  []any{csrfParam()},
			"responses": map[string]any{
				"200": jsonResponse("OK", envelopeRef("DeleteResult")),
				"401": problemResponse(),
				"403": problemResponse(),
			},
		},
	}
}

func schemaOf(t reflect.Type, schemas map[string]any) map[string]any {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), schemas)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem(), schemas)}
	case reflect.Struct:
		name := t.Name()
		if name != "" {
			if _, ok := schemas[name]; !ok {
				schemas[name] = map[string]any{"type": "object"}
				schemas[name] = structSchema(t, schemas)
			}
			return refSchema(name)
		}
		return structSchema(t, schemas)
	default:
		return map[string]any{"type": "object"}
	}
}

func structSchema(t reflect.Type, schemas map[string]any) map[string]any {
	props := map[string]any{}
	var required []any
	for _, f := range walkJSONFields(t) {
		props[f.name] = schemaOf(f.typ, schemas)
		if !f.omitempty {
			required = append(required, f.name)
		}
		if m, ok := props[f.name].(map[string]any); ok {
			if f.writeOnly {
				m["writeOnly"] = true
			}
			if enums := operations.JSONStringEnums(t.Name(), f.name); len(enums) > 0 {
				vals := make([]any, len(enums))
				for i, e := range enums {
					vals[i] = e
				}
				m["enum"] = vals
			}
		}
	}
	out := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if t.Name() == "OptionalSecret" {
		out["writeOnly"] = true
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

type jsonField struct {
	name      string
	typ       reflect.Type
	omitempty bool
	writeOnly bool
}

func walkJSONFields(t reflect.Type) []jsonField {
	var out []jsonField
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && (name == "" || name == f.Name) && f.Type.Kind() == reflect.Struct {
			out = append(out, walkJSONFields(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		writeOnly := name == "password" || name == "data" || f.Type.Name() == "OptionalSecret"
		out = append(out, jsonField{
			name:      name,
			typ:       f.Type,
			omitempty: strings.Contains(opts, "omitempty"),
			writeOnly: writeOnly,
		})
	}
	return out
}

func marshalStable(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeStable(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeStable(buf *bytes.Buffer, v any, indent int) error {
	pad := strings.Repeat("  ", indent)
	inner := strings.Repeat("  ", indent+1)
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		fmt.Fprintf(buf, "%d", x)
	case int64:
		fmt.Fprintf(buf, "%d", x)
	case uint64:
		fmt.Fprintf(buf, "%d", x)
	case float64:
		fmt.Fprintf(buf, "%v", x)
	case string:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(raw)
	case []any:
		if len(x) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteString("[\n")
		for i, item := range x {
			buf.WriteString(inner)
			if err := encodeStable(buf, item, indent+1); err != nil {
				return err
			}
			if i+1 < len(x) {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(pad)
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			buf.WriteString("{}")
			return nil
		}
		buf.WriteString("{\n")
		for i, k := range keys {
			buf.WriteString(inner)
			raw, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(raw)
			buf.WriteString(": ")
			if err := encodeStable(buf, x[k], indent+1); err != nil {
				return err
			}
			if i+1 < len(keys) {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(pad)
		buf.WriteByte('}')
	default:
		// Fall back through JSON then re-encode maps/slices for stability.
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return err
		}
		return encodeStable(buf, generic, indent)
	}
	return nil
}

func generateTS() string {
	var b strings.Builder
	b.WriteString("/* eslint-disable */\n")
	b.WriteString("// Code generated by tools/generate. DO NOT EDIT.\n")
	b.WriteString("// Generated REST types for the implemented /api/v1 surface.\n\n")
	b.WriteString("export type Revision = number;\n\n")
	b.WriteString("export interface Envelope<T> {\n")
	b.WriteString("  revision: number;\n")
	b.WriteString("  request_id: string;\n")
	b.WriteString("  data: T;\n")
	b.WriteString("}\n\n")
	b.WriteString("export interface ProblemDetails {\n")
	b.WriteString("  type: string;\n")
	b.WriteString("  title: string;\n")
	b.WriteString("  status: number;\n")
	b.WriteString("  detail: string;\n")
	b.WriteString("  code: string;\n")
	b.WriteString("  path?: string;\n")
	b.WriteString("  instance?: string;\n")
	b.WriteString("}\n\n")
	b.WriteString("export interface HealthStatus {\n")
	b.WriteString("  status: string;\n")
	b.WriteString("}\n\n")

	seen := map[string]struct{}{}
	var names []string
	types := map[string]reflect.Type{}
	for _, sample := range frozenSchemaTypes() {
		collectNamed(reflect.TypeOf(sample), seen, types, &names)
	}
	sort.Strings(names)
	for _, name := range names {
		writeTSInterface(&b, name, types[name])
	}
	return b.String()
}

func collectNamed(t reflect.Type, seen map[string]struct{}, types map[string]reflect.Type, names *[]string) {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		return
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map:
		collectNamed(t.Elem(), seen, types, names)
	case reflect.Struct:
		if t.Name() == "" || t.PkgPath() == "time" {
			return
		}
		if _, ok := seen[t.Name()]; ok {
			return
		}
		seen[t.Name()] = struct{}{}
		types[t.Name()] = t
		*names = append(*names, t.Name())
		for _, f := range walkJSONFields(t) {
			collectNamed(f.typ, seen, types, names)
		}
	}
}

func writeTSInterface(b *strings.Builder, name string, t reflect.Type) {
	fmt.Fprintf(b, "export interface %s {\n", name)
	for _, f := range walkJSONFields(t) {
		opt := ""
		if f.omitempty || f.typ.Kind() == reflect.Ptr {
			opt = "?"
		}
		fmt.Fprintf(b, "  %s%s: %s;\n", f.name, opt, tsType(f.typ, operations.JSONStringEnums(name, f.name)))
	}
	b.WriteString("}\n\n")
}

func tsType(t reflect.Type, enums []string) string {
	if len(enums) > 0 {
		parts := make([]string, len(enums))
		for i, e := range enums {
			parts[i] = strconv.Quote(e)
		}
		return strings.Join(parts, " | ")
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		return "string"
	}
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return tsType(t.Elem(), nil) + "[]"
	case reflect.Map:
		return "{ [key: string]: " + tsType(t.Elem(), nil) + " }"
	case reflect.Struct:
		if t.Name() != "" {
			return t.Name()
		}
		return "Record<string, unknown>"
	default:
		return "unknown"
	}
}

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
		"/health/live":            getPath("health.live", "Liveness probe", nil, refSchema("HealthStatus"), false),
		"/health/ready":           getPath("health.ready", "Readiness probe", nil, refSchema("HealthStatus"), false),
		"/api/openapi.json":       getPath("openapi.get", "OpenAPI document", nil, map[string]any{"type": "object"}, false),
		"/api/v1/status":          getPath(operations.IDSystemStatusGet, "Listener and snapshot status", []string{"state:read"}, envelopeRef("Status"), true),
		"/api/v1/build":           getPath(operations.IDSystemBuildGet, "Build and specification versions", []string{"state:read"}, envelopeRef("BuildInfo"), true),
		"/api/v1/policy/evaluate": postPath(operations.IDPolicyEvaluate, "Explain an authorization decision", []string{"policy:test"}, refSchema("EvaluatePolicyRequest"), envelopeRef("PolicyTrace"), false),
		"/api/v1/events":          listEventsPath(),
		"/api/v1/events/stream":   streamPath(),
		"/api/v1/tokens":          tokensCollectionPath(),
		"/api/v1/tokens/{id}":     tokensItemPath(),
		"/api/v1/session":         sessionPath(),
	}

	_ = reg

	return map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{
			"title":       openAPITitle,
			"version":     "0.16.0",
			"description": "Frozen PR-16a surface: implemented operations only (status, build, policy.evaluate, session, tokens, events). CSRF is required on cookie-authenticated mutations. cookie_secure follows listeners.http.tls.enabled.",
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
	}
	out := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
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
		out = append(out, jsonField{
			name:      name,
			typ:       f.Type,
			omitempty: strings.Contains(opts, "omitempty"),
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
	b.WriteString("// Frozen PR-16a types: status, build, policy.evaluate, session, tokens, events.\n\n")
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
		fmt.Fprintf(b, "  %s%s: %s;\n", f.name, opt, tsType(f.typ))
	}
	b.WriteString("}\n\n")
}

func tsType(t reflect.Type) string {
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
		return tsType(t.Elem()) + "[]"
	case reflect.Map:
		return "{ [key: string]: " + tsType(t.Elem()) + " }"
	case reflect.Struct:
		if t.Name() != "" {
			return t.Name()
		}
		return "Record<string, unknown>"
	default:
		return "unknown"
	}
}

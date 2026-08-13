package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func listTools(reg *operations.Registry, p auth.Principal) []map[string]any {
	if reg == nil {
		return []map[string]any{}
	}
	var ops []operations.Operation
	for _, op := range reg.List() {
		if op.MCP.Kind != "tool" || op.MCP.Name == "" || !op.Implemented {
			continue
		}
		if !hasScopes(p, op.Scopes) {
			continue
		}
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].MCP.Name < ops[j].MCP.Name })
	out := make([]map[string]any, 0, len(ops))
	for _, op := range ops {
		item := map[string]any{
			"name":         op.MCP.Name,
			"description":  op.Description,
			"inputSchema":  schemaFor(op.Request, op.Mutating),
			"outputSchema": schemaFor(op.Response, false),
			"annotations": map[string]any{
				"readOnlyHint":    !op.Mutating,
				"destructiveHint": op.Mutating && isDestructive(op.ID),
				"idempotentHint":  op.Idempotent == "true",
				"openWorldHint":   false,
			},
		}
		out = append(out, item)
	}
	return out
}

func isDestructive(id string) bool {
	return strings.HasSuffix(id, ".delete") || strings.HasSuffix(id, ".revoke") || id == operations.IDRuntimeReset
}

func callTool(ctx context.Context, opts Options, p auth.Principal, snap *state.Snapshot, raw json.RawMessage) (map[string]any, error) {
	start := time.Now()
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		opts.Metrics.MCP("unknown", "invalid_argument", "invalid_argument", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid tool params")
	}
	op, ok := toolByName(opts.Registry, params.Name)
	if !ok {
		opts.Metrics.MCP("unknown", "not_found", "not_found", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeNotFound, "unknown tool").WithDetail("name", params.Name)
	}
	ctx, span := opts.Tracer.Start(ctx, "mcp."+op.ID, observability.Attr{Key: "operation_id", Value: op.ID})
	defer span.End()
	body, rev, idem, err := splitAdapterArgs(params.Arguments)
	if err != nil {
		opts.Metrics.MCP(op.ID, "invalid_argument", "invalid_argument", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid tool arguments")
	}
	req, err := decodeRequest(op.Request, body)
	if err != nil {
		opts.Metrics.MCP(op.ID, "invalid_argument", "invalid_argument", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid tool arguments")
	}
	if opts.Registry == nil {
		opts.Metrics.MCP(op.ID, "unavailable", "unavailable", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized")
	}
	if snap == nil {
		opts.Metrics.MCP(op.ID, "unavailable", "unavailable", time.Since(start).Seconds())
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := opts.Registry.Invoke(ctx, op.ID, snap, operations.Input{
		Actor:            p.Actor(),
		ExpectedRevision: rev,
		IdempotencyKey:   idem,
		Request:          req,
	})
	if err != nil {
		result, code := observability.ResultFromError(err)
		opts.Metrics.MCP(op.ID, result, code, time.Since(start).Seconds())
		return nil, err
	}
	opts.Metrics.MCP(op.ID, observability.ResultSuccess, "none", time.Since(start).Seconds())
	text, _ := json.Marshal(res.Data)
	if len(text) == 0 {
		text = []byte("ok")
	}
	out := map[string]any{
		"structuredContent": res.Data,
		"resultType":        resultTypeComplete,
		"content":           []map[string]string{{"type": "text", "text": string(text)}},
	}
	if !op.Mutating {
		out["ttlMs"] = 0
		out["cacheScope"] = cacheScopePrivate
	}
	return out, nil
}

func listResources(reg *operations.Registry, p auth.Principal) []map[string]any {
	if reg == nil {
		return []map[string]any{}
	}
	seen := map[string]struct{}{}
	var uris []string
	byURI := map[string]operations.Operation{}
	for _, op := range reg.List() {
		if op.MCP.Resource == "" || !op.Implemented || op.MCP.Kind != "tool" {
			continue
		}
		if !hasScopes(p, op.Scopes) {
			continue
		}
		if _, dup := seen[op.MCP.Resource]; dup {
			continue
		}
		seen[op.MCP.Resource] = struct{}{}
		uris = append(uris, op.MCP.Resource)
		byURI[op.MCP.Resource] = op
	}
	sort.Strings(uris)
	out := make([]map[string]any, 0, len(uris))
	for _, uri := range uris {
		op := byURI[uri]
		out = append(out, map[string]any{
			"uri":         uri,
			"name":        resourceName(uri),
			"description": op.Description,
			"mimeType":    "application/json",
		})
	}
	return out
}

func resourceName(uri string) string {
	if i := strings.LastIndex(uri, "/"); i >= 0 && i+1 < len(uri) {
		return uri[i+1:]
	}
	if i := strings.Index(uri, "://"); i >= 0 {
		return uri[i+3:]
	}
	return uri
}

func readResource(ctx context.Context, opts Options, p auth.Principal, snap *state.Snapshot, raw json.RawMessage) (map[string]any, error) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &params); err != nil || params.URI == "" {
		return nil, domain.NewError(domain.CodeInvalidArgument, "uri is required")
	}
	op, ok := resourceOp(opts.Registry, params.URI)
	if !ok {
		return nil, domain.NewError(domain.CodeNotFound, "unknown resource").WithDetail("uri", params.URI)
	}
	if !hasScopes(p, op.Scopes) {
		return nil, domain.NewError(domain.CodePermissionDenied, "missing required scope")
	}
	if opts.Registry == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized")
	}
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req := reflect.Zero(op.Request).Interface()
	res, err := opts.Registry.Invoke(ctx, op.ID, snap, operations.Input{
		Actor:   p.Actor(),
		Request: req,
	})
	if err != nil {
		return nil, err
	}
	text, err := json.Marshal(res.Data)
	if err != nil {
		return nil, domain.NewError(domain.CodeInternal, "cannot encode resource")
	}
	return map[string]any{
		"contents": []map[string]any{{
			"uri":      params.URI,
			"mimeType": "application/json",
			"text":     string(text),
		}},
		"resultType": resultTypeComplete,
		"ttlMs":      0,
		"cacheScope": cacheScopePrivate,
	}, nil
}

func toolByName(reg *operations.Registry, name string) (operations.Operation, bool) {
	if reg == nil || name == "" {
		return operations.Operation{}, false
	}
	for _, op := range reg.List() {
		if op.MCP.Kind == "tool" && op.MCP.Name == name && op.Implemented {
			return op, true
		}
	}
	return operations.Operation{}, false
}

func resourceOp(reg *operations.Registry, uri string) (operations.Operation, bool) {
	if reg == nil || uri == "" {
		return operations.Operation{}, false
	}
	for _, op := range reg.List() {
		if op.MCP.Kind == "tool" && op.MCP.Resource == uri && op.Implemented {
			return op, true
		}
	}
	return operations.Operation{}, false
}

func splitAdapterArgs(raw json.RawMessage) (json.RawMessage, *domain.Revision, string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil, "", nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, "", err
	}
	var rev *domain.Revision
	if v, ok := m["expected_revision"]; ok {
		n, err := parseRevision(v)
		if err != nil {
			return nil, nil, "", err
		}
		r := domain.Revision(n)
		rev = &r
		delete(m, "expected_revision")
	}
	var idem string
	if v, ok := m["idempotency_key"]; ok {
		if err := json.Unmarshal(v, &idem); err != nil {
			return nil, nil, "", err
		}
		delete(m, "idempotency_key")
	}
	body, err := json.Marshal(m)
	return body, rev, idem, err
}

func parseRevision(raw json.RawMessage) (uint64, error) {
	var n uint64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}

func decodeRequest(typ reflect.Type, raw json.RawMessage) (any, error) {
	if typ == nil {
		return nil, nil
	}
	ptr := reflect.New(typ)
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return ptr.Elem().Interface(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(ptr.Interface()); err != nil {
		return nil, err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, err
	}
	return ptr.Elem().Interface(), nil
}

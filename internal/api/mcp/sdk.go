package mcp

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func newSDKServer(opts Options, p auth.Principal) *sdkmcp.Server {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "taclab",
		Version: opts.Version,
	}, &sdkmcp.ServerOptions{
		Instructions: "TacLab TACACS+ / MCP lab appliance. Tools and resources share the REST operation registry.",
		Capabilities: &sdkmcp.ServerCapabilities{
			Tools:     &sdkmcp.ToolCapabilities{ListChanged: true},
			Resources: &sdkmcp.ResourceCapabilities{ListChanged: true, Subscribe: true},
		},
	})
	bindSDKTools(s, opts, p)
	bindSDKResources(s, opts, p)
	s.AddReceivingMiddleware(scopeFilterMiddleware(opts, p))
	return s
}

func scopeFilterMiddleware(opts Options, p auth.Principal) sdkmcp.Middleware {
	allowedTools := map[string]struct{}{}
	allowedRes := map[string]struct{}{}
	if opts.Registry != nil {
		for _, op := range opts.Registry.List() {
			if !op.Implemented || !hasScopes(p, op.Scopes) {
				continue
			}
			if op.MCP.Kind == "tool" && op.MCP.Name != "" {
				allowedTools[op.MCP.Name] = struct{}{}
			}
			if op.MCP.Resource != "" {
				allowedRes[op.MCP.Resource] = struct{}{}
			}
		}
	}
	return func(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
		return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil {
				return res, err
			}
			switch method {
			case "server/discover":
				if disc, ok := res.(*sdkmcp.DiscoverResult); ok {
					disc.SupportedVersions = []string{protocolVersion}
				}
			case "tools/list":
				if list, ok := res.(*sdkmcp.ListToolsResult); ok {
					keep := make([]*sdkmcp.Tool, 0, len(list.Tools))
					for _, t := range list.Tools {
						if _, ok := allowedTools[t.Name]; ok {
							keep = append(keep, t)
						}
					}
					list.Tools = keep
					markPrivate(list)
				}
			case "resources/list":
				if list, ok := res.(*sdkmcp.ListResourcesResult); ok {
					keep := make([]*sdkmcp.Resource, 0, len(list.Resources))
					for _, r := range list.Resources {
						if _, ok := allowedRes[r.URI]; ok {
							keep = append(keep, r)
						}
					}
					list.Resources = keep
					markPrivate(list)
				}
			case "resources/read":
				if read, ok := res.(*sdkmcp.ReadResourceResult); ok {
					markPrivate(read)
				}
			}
			return res, nil
		}
	}
}

func markPrivate(c interface{ GetTTLMs() int }) {
	switch v := c.(type) {
	case *sdkmcp.ListToolsResult:
		v.TTLMs = 0
		v.CacheScope = cacheScopePrivate
	case *sdkmcp.ListResourcesResult:
		v.TTLMs = 0
		v.CacheScope = cacheScopePrivate
	case *sdkmcp.ReadResourceResult:
		v.TTLMs = 0
		v.CacheScope = cacheScopePrivate
	}
}

func bindSDKTools(s *sdkmcp.Server, opts Options, p auth.Principal) {
	if opts.Registry == nil {
		return
	}
	var ops []operations.Operation
	for _, op := range opts.Registry.List() {
		if op.MCP.Kind != "tool" || op.MCP.Name == "" || !op.Implemented {
			continue
		}
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].MCP.Name < ops[j].MCP.Name })
	for _, op := range ops {
		op := op
		ro := !op.Mutating
		open := false
		dest := op.Mutating && isDestructive(op.ID)
		s.AddTool(&sdkmcp.Tool{
			Name:         op.MCP.Name,
			Description:  op.Description,
			InputSchema:  schemaFor(op.Request, op.Mutating),
			OutputSchema: schemaFor(op.Response, false),
			Annotations: &sdkmcp.ToolAnnotations{
				ReadOnlyHint:    ro,
				DestructiveHint: &dest,
				IdempotentHint:  op.Idempotent == "true",
				OpenWorldHint:   &open,
			},
		}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
			return invokeSDKTool(ctx, opts, p, op.MCP.Name, req.Params.Arguments)
		})
	}
}

func bindSDKResources(s *sdkmcp.Server, opts Options, p auth.Principal) {
	if opts.Registry == nil {
		return
	}
	seen := map[string]struct{}{}
	var uris []string
	byURI := map[string]operations.Operation{}
	for _, op := range opts.Registry.List() {
		if op.MCP.Resource == "" || !op.Implemented || op.MCP.Kind != "tool" {
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
	for _, uri := range uris {
		uri := uri
		op := byURI[uri]
		s.AddResource(&sdkmcp.Resource{
			URI:         uri,
			Name:        resourceName(uri),
			Description: op.Description,
			MIMEType:    "application/json",
		}, func(ctx context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
			return invokeSDKResource(ctx, opts, p, req.Params.URI)
		})
	}
}

func invokeSDKTool(ctx context.Context, opts Options, p auth.Principal, name string, args json.RawMessage) (*sdkmcp.CallToolResult, error) {
	env := struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}{Name: name, Arguments: args}
	params, err := json.Marshal(env)
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "invalid tool arguments"}
	}
	out, err := callTool(ctx, opts, p, snapshotOf(opts), params)
	if err != nil {
		return nil, protocolError(err)
	}
	text, _ := json.Marshal(out["structuredContent"])
	if len(text) == 0 || string(text) == "null" {
		text = []byte("ok")
	}
	return &sdkmcp.CallToolResult{
		Content:           []sdkmcp.Content{&sdkmcp.TextContent{Text: string(text)}},
		StructuredContent: out["structuredContent"],
	}, nil
}

func invokeSDKResource(ctx context.Context, opts Options, p auth.Principal, uri string) (*sdkmcp.ReadResourceResult, error) {
	raw, _ := json.Marshal(map[string]any{"uri": uri})
	out, err := readResource(ctx, opts, p, snapshotOf(opts), raw)
	if err != nil {
		if de, ok := domain.AsError(err); ok && de.Code == domain.CodeNotFound {
			return nil, sdkmcp.ResourceNotFoundError(uri)
		}
		return nil, protocolError(err)
	}
	contents, _ := out["contents"].([]map[string]any)
	res := &sdkmcp.ReadResourceResult{}
	for _, c := range contents {
		item := &sdkmcp.ResourceContents{URI: uri, MIMEType: "application/json"}
		if t, ok := c["text"].(string); ok {
			item.Text = t
		}
		res.Contents = append(res.Contents, item)
	}
	return res, nil
}

func protocolError(err error) error {
	de, ok := domain.AsError(err)
	if !ok {
		return err
	}
	return &jsonrpc.Error{Code: int64(rpcCode(de.Code)), Message: de.Message, Data: mustRaw(errorData(de))}
}

func mustRaw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

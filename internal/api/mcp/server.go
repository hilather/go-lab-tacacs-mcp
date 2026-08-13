package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	protocolVersion = "2026-07-28"
	defaultMaxBody  = 2 << 20

	headerProtocolVersion = "MCP-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaSubscriptionID     = "io.modelcontextprotocol/subscriptionId"
	jsonRPCVersion         = "2.0"
	codeParseError         = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeInternal           = -32603
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
	resultTypeComplete     = "complete"
	cacheScopePrivate      = "private"
	resourceEventsRecent   = "taclab://events/recent"
)

// FrozenMCPMethods is the 2026-07-28 RPC surface this adapter implements.
var FrozenMCPMethods = []string{
	"server/discover",
	"tools/list",
	"tools/call",
	"resources/list",
	"resources/read",
	"subscriptions/listen",
}

// Options construct the Streamable HTTP handler.
type Options struct {
	Registry     *operations.Registry
	Snapshot     func() *state.Snapshot
	Auth         *auth.Service
	Events       *events.Ring
	MCP          config.MCP
	Version      string
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	MaxBody      int64
	Metrics      *observability.Recorder
	Tracer       *observability.Tracer
	// Done is closed on HTTP server shutdown (RegisterOnShutdown). Listen
	// writes resultType complete so SIGTERM is not an abrupt SSE drop.
	Done <-chan struct{}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type paramsMeta struct {
	Meta map[string]any `json:"_meta"`
}

// Handler is POST /mcp. GET and DELETE return 405.
func Handler(opts Options) http.Handler {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodDelete:
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		case http.MethodPost:
		default:
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := checkOrigin(r, opts.MCP); err != nil {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		snap := snapshotOf(opts)
		p, err := authenticate(r, opts.Auth, snap)
		if err != nil {
			w.Header().Set("WWW-Authenticate", auth.BearerRealm)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		max := opts.MaxBody
		if max <= 0 {
			max = defaultMaxBody
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeParseError, Message: "parse error"}})
			return
		}
		if int64(len(body)) > max {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeInvalidRequest, Message: "request body too large"}})
			return
		}

		headerVer := strings.TrimSpace(r.Header.Get(headerProtocolVersion))
		if headerVer == "" {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: headerMismatch("MCP-Protocol-Version is required")})
			return
		}
		if headerVer != protocolVersion {
			writeRPC(w, http.StatusBadRequest, rpcResponse{
				JSONRPC: jsonRPCVersion,
				Error:   unsupportedVersion(headerVer),
			})
			return
		}

		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeParseError, Message: "parse error"}})
			return
		}
		if req.JSONRPC != "" && req.JSONRPC != jsonRPCVersion {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidRequest, Message: "jsonrpc must be 2.0"}})
			return
		}
		if isNotification(req.ID) {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		headerMethod := strings.TrimSpace(r.Header.Get(headerMethod))
		if headerMethod == "" {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Method is required")})
			return
		}
		if req.Method == "" {
			req.Method = headerMethod
		} else if headerMethod != req.Method {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Method does not match body method")})
			return
		}

		meta := extractMeta(req.Params)
		if meta == nil {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("params._meta is required")})
			return
		}
		metaVer, _ := meta[metaProtocolVersion].(string)
		if metaVer == "" {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("params._meta protocolVersion is required")})
			return
		}
		if metaVer != headerVer {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("MCP-Protocol-Version does not match _meta protocolVersion")})
			return
		}
		if metaVer != protocolVersion {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: unsupportedVersion(metaVer)})
			return
		}
		if _, ok := meta[metaClientCapabilities]; !ok {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: &rpcError{
				Code:    codeInvalidParams,
				Message: "params._meta clientCapabilities is required",
			}})
			return
		}

		if nameRequired(req.Method) {
			want, err := nameFromParams(req.Method, req.Params)
			if err != nil {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch(err.Error())})
				return
			}
			got, err := decodeHeaderValue(r.Header.Get(headerName))
			if err != nil {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Name is malformed")})
				return
			}
			if got == "" {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Name is required")})
				return
			}
			if got != want {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Name does not match body")})
				return
			}
		}

		switch req.Method {
		case "subscriptions/listen":
			handleListen(w, r, opts, p, req)
			return
		case "prompts/get":
			writeRPC(w, http.StatusNotFound, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: &rpcError{Code: codeMethodNotFound, Message: "method not found"}})
			return
		}

		res, httpStatus := dispatch(r.Context(), opts, p, snap, req)
		writeRPC(w, httpStatus, res)
	})
}

func dispatch(ctx context.Context, opts Options, p auth.Principal, snap *state.Snapshot, req rpcRequest) (rpcResponse, int) {
	out := rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID}
	switch req.Method {
	case "server/discover":
		out.Result = discoverResult(opts)
		return out, http.StatusOK
	case "tools/list":
		out.Result = map[string]any{
			"tools":      listTools(opts.Registry, p),
			"resultType": resultTypeComplete,
			"ttlMs":      0,
			"cacheScope": cacheScopePrivate,
		}
		return out, http.StatusOK
	case "tools/call":
		result, err := callTool(ctx, opts, p, snap, req.Params)
		if err != nil {
			out.Error = toolRPCError(err)
			return out, http.StatusOK
		}
		out.Result = result
		return out, http.StatusOK
	case "resources/list":
		out.Result = map[string]any{
			"resources":  listResources(opts.Registry, p),
			"resultType": resultTypeComplete,
			"ttlMs":      0,
			"cacheScope": cacheScopePrivate,
		}
		return out, http.StatusOK
	case "resources/read":
		result, err := readResource(ctx, opts, p, snap, req.Params)
		if err != nil {
			out.Error = toolRPCError(err)
			return out, http.StatusOK
		}
		out.Result = result
		return out, http.StatusOK
	default:
		out.Error = &rpcError{Code: codeMethodNotFound, Message: "method not found"}
		return out, http.StatusNotFound
	}
}

func discoverResult(opts Options) map[string]any {
	return map[string]any{
		"protocolVersion":           protocolVersion,
		"supportedProtocolVersions": []string{protocolVersion},
		"serverInfo": map[string]string{
			"name":    "taclab",
			"version": opts.Version,
		},
		"capabilities": map[string]any{
			"tools":         map[string]any{"listChanged": true},
			"resources":     map[string]any{"listChanged": true, "subscribe": true},
			"subscriptions": map[string]any{},
		},
		"resultType": resultTypeComplete,
		"ttlMs":      0,
		"cacheScope": cacheScopePrivate,
	}
}

func authenticate(r *http.Request, svc *auth.Service, snap *state.Snapshot) (auth.Principal, error) {
	if svc == nil {
		return auth.Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	return svc.Authenticate(auth.Request{Authorization: r.Header.Get("Authorization")}, snap)
}

func snapshotOf(opts Options) *state.Snapshot {
	if opts.Snapshot == nil {
		return nil
	}
	return opts.Snapshot()
}

func checkOrigin(r *http.Request, cfg config.MCP) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if cfg.RequireOrigin {
			return domain.NewError(domain.CodePermissionDenied, "origin required")
		}
		return nil
	}
	for _, allowed := range cfg.AllowedOrigins {
		if origin == allowed {
			return nil
		}
	}
	host := r.Host
	if host != "" && (origin == "http://"+host || origin == "https://"+host) {
		return nil
	}
	return domain.NewError(domain.CodePermissionDenied, "origin not allowed")
}

func extractMeta(params json.RawMessage) map[string]any {
	if len(bytes.TrimSpace(params)) == 0 {
		return nil
	}
	var env paramsMeta
	if err := json.Unmarshal(params, &env); err != nil {
		return nil
	}
	return env.Meta
}

func nameRequired(method string) bool {
	switch method {
	case "tools/call", "resources/read", "prompts/get":
		return true
	default:
		return false
	}
}

func nameFromParams(method string, params json.RawMessage) (string, error) {
	var envelope struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &envelope); err != nil {
			return "", err
		}
	}
	switch method {
	case "resources/read":
		if envelope.URI == "" {
			return "", errString("params.uri is required")
		}
		return envelope.URI, nil
	default:
		if envelope.Name == "" {
			return "", errString("params.name is required")
		}
		return envelope.Name, nil
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func decodeHeaderValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	const prefix = "=?base64?"
	const suffix = "?="
	if strings.HasPrefix(raw, prefix) && strings.HasSuffix(raw, suffix) && len(raw) >= len(prefix)+len(suffix) {
		enc := raw[len(prefix) : len(raw)-len(suffix)]
		b, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return raw, nil
}

func isNotification(id json.RawMessage) bool {
	s := strings.TrimSpace(string(id))
	return s == "" || s == "null"
}

func headerMismatch(msg string) *rpcError {
	return &rpcError{Code: codeHeaderMismatch, Message: msg}
}

func unsupportedVersion(requested string) *rpcError {
	return &rpcError{
		Code:    codeUnsupportedVersion,
		Message: "Unsupported protocol version",
		Data: map[string]any{
			"supported": []string{protocolVersion},
			"requested": requested,
		},
	}
}

func toolRPCError(err error) *rpcError {
	de, ok := domain.AsError(err)
	if !ok {
		return &rpcError{Code: codeInternal, Message: "internal error"}
	}
	out := &rpcError{Code: rpcCode(de.Code), Message: de.Message, Data: errorData(de)}
	return out
}

func errorData(de domain.Error) map[string]any {
	data := map[string]any{"code": string(de.Code)}
	if de.Path != "" {
		data["path"] = de.Path
	}
	return data
}

func rpcCode(code domain.Code) int {
	switch code {
	case domain.CodeInvalidArgument:
		return codeInvalidParams
	case domain.CodeNotFound:
		return codeMethodNotFound
	default:
		return -32000
	}
}

func writeRPC(w http.ResponseWriter, status int, res rpcResponse) {
	if res.JSONRPC == "" {
		res.JSONRPC = jsonRPCVersion
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(res)
}

func hasScopes(p auth.Principal, required []string) bool {
	return auth.Satisfies(p.Scopes, required)
}

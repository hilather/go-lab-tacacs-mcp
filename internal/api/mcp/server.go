package mcp

import (
	"bytes"
	"context"
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

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
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

type principalCtxKey struct{}

// Handler is POST /mcp. GET and DELETE return 405.
// Framing, headers, server/discover, tools, and resources go through the
// official Go SDK (v1.7.0). Lab bearer, origin policy, and
// subscriptions/listen (URI-only) stay in this adapter.
func Handler(opts Options) http.Handler {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	max := opts.MaxBody
	if max <= 0 {
		max = defaultMaxBody
	}
	sdk := sdkmcp.NewStreamableHTTPHandler(func(r *http.Request) *sdkmcp.Server {
		p, _ := r.Context().Value(principalCtxKey{}).(auth.Principal)
		return newSDKServer(opts, p)
	}, &sdkmcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		DisableLocalhostProtection:   true,
		PropagateRequestCancellation: true,
		MaxRequestBodyBytes:          max,
	})
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

		// Official streamable transport requires both Accept types.
		if r.Header.Get("Accept") == "" {
			r.Header.Set("Accept", "application/json, text/event-stream")
		}

		method := strings.TrimSpace(r.Header.Get(headerMethod))
		if method == "subscriptions/listen" {
			body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
			if err != nil {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeParseError, Message: "parse error"}})
				return
			}
			if int64(len(body)) > max {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeInvalidRequest, Message: "request body too large"}})
				return
			}
			var req rpcRequest
			if err := json.Unmarshal(body, &req); err != nil {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, Error: &rpcError{Code: codeParseError, Message: "parse error"}})
				return
			}
			if req.Method != "" && req.Method != method {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: headerMismatch("Mcp-Method does not match body method")})
				return
			}
			req.Method = method
			if rpcErr := metaRPCError(headerVer, req.Params); rpcErr != nil {
				writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: jsonRPCVersion, ID: req.ID, Error: rpcErr})
				return
			}
			handleListen(w, r, opts, p, req)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, p))
		sdk.ServeHTTP(w, r)
	})
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

func metaRPCError(headerVer string, params json.RawMessage) *rpcError {
	meta := extractMeta(params)
	if meta == nil {
		return headerMismatch("params._meta is required")
	}
	metaVer, _ := meta[metaProtocolVersion].(string)
	if metaVer == "" {
		return headerMismatch("params._meta protocolVersion is required")
	}
	if metaVer != headerVer {
		return headerMismatch("MCP-Protocol-Version does not match _meta protocolVersion")
	}
	if metaVer != protocolVersion {
		return unsupportedVersion(metaVer)
	}
	if _, ok := meta[metaClientCapabilities]; !ok {
		return &rpcError{Code: codeInvalidParams, Message: "params._meta clientCapabilities is required"}
	}
	return nil
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
	default:
		// Do not use -32601 for domain not-found: the official SDK treats any
		// WireError with that code as JSON-RPC "method not found" and rewrites
		// the message, dropping application data.
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

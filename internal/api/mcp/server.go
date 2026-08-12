package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const protocolVersion = "2026-07-28"

// Options construct the Streamable HTTP handler.
type Options struct {
	Registry *operations.Registry
	Snapshot func() *state.Snapshot
	Auth     *auth.Verifier
	MCP      config.MCP
	Version  string
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
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Handler is POST /mcp. GET and DELETE return 405.
//
// This is a thin 2026-07-28 skeleton (server/discover + two tools). The
// official Go SDK requires Go 1.25; this repo is pinned to 1.24.5. PR-17
// replaces this adapter with the pinned SDK.
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
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := checkOrigin(r, opts.MCP); err != nil {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		p, err := authenticate(r, opts.Auth)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="taclab"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			return
		}
		if req.Method == "" {
			req.Method = r.Header.Get("Mcp-Method")
		}
		if headerMethod := r.Header.Get("Mcp-Method"); headerMethod != "" && req.Method != "" && headerMethod != req.Method {
			writeRPC(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32020, Message: "HeaderMismatch"}})
			return
		}
		res, httpStatus := dispatch(r.Context(), opts, p, req)
		writeRPC(w, httpStatus, res)
	})
}

func dispatch(ctx context.Context, opts Options, p auth.Principal, req rpcRequest) (rpcResponse, int) {
	out := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "server/discover":
		out.Result = map[string]any{
			"protocolVersion":           protocolVersion,
			"supportedProtocolVersions": []string{protocolVersion},
			"serverInfo": map[string]string{
				"name":    "taclab",
				"version": opts.Version,
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"resultType": "complete",
		}
		return out, http.StatusOK
	case "tools/list":
		out.Result = map[string]any{
			"tools":      listTools(opts.Registry, p),
			"resultType": "complete",
			"ttlMs":      0,
			"cacheScope": "private",
		}
		return out, http.StatusOK
	case "tools/call":
		result, err := callTool(ctx, opts, p, req.Params)
		if err != nil {
			de, ok := domain.AsError(err)
			if !ok {
				out.Error = &rpcError{Code: -32603, Message: err.Error()}
				return out, http.StatusOK
			}
			out.Error = &rpcError{Code: rpcCode(de.Code), Message: de.Message}
			return out, http.StatusOK
		}
		out.Result = result
		return out, http.StatusOK
	default:
		out.Error = &rpcError{Code: -32601, Message: "method not found"}
		return out, http.StatusNotFound
	}
}

func listTools(reg *operations.Registry, p auth.Principal) []map[string]any {
	if reg == nil {
		return []map[string]any{}
	}
	var names []string
	for _, id := range []string{operations.IDSystemStatusGet, operations.IDPolicyEvaluate} {
		op, ok := reg.Lookup(id)
		if !ok || op.MCP.Name == "" {
			continue
		}
		if !hasScopes(p, op.Scopes) {
			continue
		}
		names = append(names, op.MCP.Name)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"name": n})
	}
	return out
}

func callTool(ctx context.Context, opts Options, p auth.Principal, raw json.RawMessage) (map[string]any, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "invalid tool params")
	}
	var id string
	var req any
	switch params.Name {
	case "taclab.system.status.get":
		id = operations.IDSystemStatusGet
		req = operations.GetStatusRequest{}
	case "taclab.policy.evaluate":
		id = operations.IDPolicyEvaluate
		var ev operations.EvaluatePolicyRequest
		if len(params.Arguments) > 0 {
			if err := decodeStrict(params.Arguments, &ev); err != nil {
				return nil, domain.NewError(domain.CodeInvalidArgument, "invalid tool arguments")
			}
		}
		req = ev
	default:
		return nil, domain.NewError(domain.CodeNotFound, "unknown tool")
	}
	if opts.Registry == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "operation registry is not initialized")
	}
	var snap *state.Snapshot
	if opts.Snapshot != nil {
		snap = opts.Snapshot()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := opts.Registry.Invoke(ctx, id, snap, operations.Input{Actor: p.Actor(), Request: req})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"structuredContent": res.Data,
		"resultType":        "complete",
		"content":           []map[string]string{{"type": "text", "text": "ok"}},
	}, nil
}

func hasScopes(p auth.Principal, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := map[string]struct{}{}
	for _, s := range p.Scopes {
		have[s] = struct{}{}
	}
	for _, s := range required {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

func authenticate(r *http.Request, v *auth.Verifier) (auth.Principal, error) {
	raw, ok := auth.ParseBearer(r.Header.Get("Authorization"))
	if !ok {
		return auth.Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	if v == nil {
		return auth.Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	return v.Authenticate(raw)
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

func writeRPC(w http.ResponseWriter, status int, res rpcResponse) {
	if res.JSONRPC == "" {
		res.JSONRPC = "2.0"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(res)
}

func decodeStrict(raw json.RawMessage, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func rpcCode(code domain.Code) int {
	switch code {
	case domain.CodeInvalidArgument:
		return -32602
	case domain.CodeNotFound:
		return -32601
	default:
		return -32000
	}
}

package operations

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Actor is the authenticated principal. Empty ID and scopes means unauthenticated.
type Actor struct {
	ID     string
	Scopes []string
}

// Input is adapter-independent handler input. ExpectedRevision and IdempotencyKey
// are accepted on every call so REST and MCP share one signature.
type Input struct {
	Actor            Actor
	ExpectedRevision *domain.Revision
	IdempotencyKey   string
	Request          any
}

// Result is the common operation output. Adapters wrap Data with request_id.
type Result struct {
	Revision domain.Revision
	Data     any
}

// Operation is one registered capability. Handler bodies are not exported.
type Operation struct {
	ID           string
	Description  string
	Parity       string
	Mutating     bool
	Idempotent   string
	Scopes       []string
	RequestType  string
	ResponseType string
	REST         RESTBinding
	MCP          MCPBinding
	AuditEvent   string
	Status       string
	Implemented  bool
	Request      reflect.Type
	Response     reflect.Type
}

type handleFunc func(ctx context.Context, snap *state.Snapshot, in Input) (any, error)

type registered struct {
	op      Operation
	handle  handleFunc
	reqType reflect.Type
	resp    reflect.Type
}

// Registry is the typed operation table shared by REST and MCP.
type Registry struct {
	ops  map[string]registered
	list []Operation
}

// New loads handlers for every operation in spec. Unknown handler IDs and
// missing YAML type names fail closed.
func New(spec *Spec, deps Deps) (*Registry, error) {
	return assemble(spec, implementedHandlers(deps), defaultCatalog())
}

// NewFromRepo loads api/operations.yaml from the module containing start.
func NewFromRepo(start string, deps Deps) (*Registry, error) {
	spec, err := LoadRepoSpec(start)
	if err != nil {
		return nil, err
	}
	return New(spec, deps)
}

func assemble(spec *Spec, implemented map[string]handleFunc, catalog map[string]reflect.Type) (*Registry, error) {
	if spec == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "operation spec is required")
	}
	if catalog == nil {
		catalog = defaultCatalog()
	}
	ids := make(map[string]struct{}, len(spec.Operations))
	for _, op := range spec.Operations {
		if op.ID == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "operation id is required")
		}
		if _, dup := ids[op.ID]; dup {
			return nil, domain.NewError(domain.CodeAlreadyExists, "duplicate operation id").WithDetail("operation", op.ID)
		}
		ids[op.ID] = struct{}{}
	}
	for id := range implemented {
		if _, ok := ids[id]; !ok {
			return nil, domain.NewError(domain.CodeInvalidArgument, "handler is not listed in the operation spec").WithDetail("operation", id)
		}
	}
	reg := &Registry{
		ops:  make(map[string]registered, len(spec.Operations)),
		list: make([]Operation, 0, len(spec.Operations)),
	}
	for _, specOp := range spec.Operations {
		req, ok := catalog[specOp.RequestType]
		if !ok {
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown request_type").
				WithDetail("operation", specOp.ID).
				WithDetail("request_type", specOp.RequestType)
		}
		resp, ok := catalog[specOp.ResponseType]
		if !ok {
			return nil, domain.NewError(domain.CodeInvalidArgument, "unknown response_type").
				WithDetail("operation", specOp.ID).
				WithDetail("response_type", specOp.ResponseType)
		}
		for i, scope := range specOp.Scopes {
			if !config.ValidScope(scope) {
				return nil, domain.NewError(domain.CodeInvalidArgument, "unknown scope").
					WithPath(fmt.Sprintf("operations/%s/scopes[%d]", specOp.ID, i)).
					WithDetail("scope", scope)
			}
		}
		fn, hasHandler := implemented[specOp.ID]
		if !hasHandler {
			fn = stubHandler(specOp.ID)
		}
		op := Operation{
			ID:           specOp.ID,
			Description:  specOp.Description,
			Parity:       specOp.Parity,
			Mutating:     specOp.Mutating,
			Idempotent:   specOp.Idempotent,
			Scopes:       cloneStrings(specOp.Scopes),
			RequestType:  specOp.RequestType,
			ResponseType: specOp.ResponseType,
			REST:         specOp.REST,
			MCP:          specOp.MCP,
			AuditEvent:   specOp.AuditEvent,
			Status:       specOp.Status,
			Implemented:  hasHandler,
			Request:      req,
			Response:     resp,
		}
		reg.ops[specOp.ID] = registered{op: op, handle: fn, reqType: req, resp: resp}
		reg.list = append(reg.list, op)
	}
	return reg, nil
}

// Lookup returns a copy of the registered operation.
func (r *Registry) Lookup(id string) (Operation, bool) {
	if r == nil {
		return Operation{}, false
	}
	got, ok := r.ops[id]
	if !ok {
		return Operation{}, false
	}
	return copyOperation(got.op), true
}

// List returns operations in YAML order.
func (r *Registry) List() []Operation {
	if r == nil {
		return nil
	}
	out := make([]Operation, len(r.list))
	for i, op := range r.list {
		out[i] = copyOperation(op)
	}
	return out
}

// ImplementedIDs returns implemented operation IDs in sorted order.
func (r *Registry) ImplementedIDs() []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, op := range r.list {
		if op.Implemented {
			out = append(out, op.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Invoke runs one operation against a published snapshot. No HTTP is involved.
func (r *Registry) Invoke(ctx context.Context, id string, snap *state.Snapshot, in Input) (Result, error) {
	if r == nil {
		return Result{}, domain.NewError(domain.CodeInternal, "operation registry is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	got, ok := r.ops[id]
	if !ok {
		return Result{}, domain.NewError(domain.CodeNotFound, "unknown operation").WithDetail("operation", id)
	}
	if err := authorize(in.Actor, got.op.Scopes); err != nil {
		return Result{}, err
	}
	if snap == nil {
		return Result{}, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, err := coerceRequest(in.Request, got.reqType)
	if err != nil {
		return Result{}, err
	}
	in.Request = req
	data, err := got.handle(ctx, snap, in)
	if err != nil {
		return Result{}, err
	}
	if data != nil && got.resp != nil && reflect.TypeOf(data) != got.resp {
		return Result{}, domain.NewError(domain.CodeInternal, "handler returned unexpected response type").
			WithDetail("operation", id).
			WithDetail("got", reflect.TypeOf(data).Name()).
			WithDetail("want", got.resp.Name())
	}
	return Result{Revision: snap.Revision, Data: data}, nil
}

func authorize(actor Actor, required []string) error {
	if len(required) == 0 {
		return nil
	}
	if actor.ID == "" && len(actor.Scopes) == 0 {
		return domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	have := make(map[string]struct{}, len(actor.Scopes))
	for _, s := range actor.Scopes {
		have[s] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := have[scope]; !ok {
			return domain.NewError(domain.CodePermissionDenied, "missing required scope").WithDetail("scope", scope)
		}
	}
	return nil
}

func coerceRequest(body any, want reflect.Type) (any, error) {
	if want == nil {
		return nil, nil
	}
	if body == nil {
		return reflect.Zero(want).Interface(), nil
	}
	got := reflect.TypeOf(body)
	if got == want {
		return body, nil
	}
	if got.Kind() == reflect.Ptr && got.Elem() == want {
		v := reflect.ValueOf(body)
		if v.IsNil() {
			return reflect.Zero(want).Interface(), nil
		}
		return v.Elem().Interface(), nil
	}
	return nil, domain.NewError(domain.CodeInvalidArgument, "request type mismatch").
		WithDetail("got", got.Name()).
		WithDetail("want", want.Name())
}

func copyOperation(op Operation) Operation {
	op.Scopes = cloneStrings(op.Scopes)
	return op
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

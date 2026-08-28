package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleSessionCreate(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.Sessions == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "session service is not configured")
		}
		if in.Actor.ID == "" {
			return nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
		}
		return deps.Sessions.Create(in.Actor, snap)
	}
}

func handleSessionGet(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.Sessions == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "session service is not configured")
		}
		id := in.Actor.SessionID
		if id == "" {
			return nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
		}
		return deps.Sessions.Get(id, snap)
	}
}

func handleSessionDelete(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.Sessions == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "session service is not configured")
		}
		if in.Actor.ID == "" && in.Actor.SessionID == "" {
			return nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
		}
		id := in.Actor.SessionID
		if id == "" {
			return nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
		}
		req, _ := in.Request.(DeleteSessionRequest)
		if req.SessionID != "" && req.SessionID != id {
			return nil, domain.NewError(domain.CodePermissionDenied, "session id does not match the authenticated session")
		}
		out, err := deps.Sessions.Delete(id)
		if err != nil {
			return nil, err
		}
		if snap != nil && out.Revision == 0 {
			out.Revision = snap.Revision
		}
		return out, nil
	}
}

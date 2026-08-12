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

func handleSessionDelete(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.Sessions == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "session service is not configured")
		}
		req, _ := in.Request.(DeleteSessionRequest)
		id := req.SessionID
		if id == "" {
			id = in.Actor.SessionID
		}
		if id == "" {
			return nil, domain.NewError(domain.CodeUnauthenticated, "authentication required")
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

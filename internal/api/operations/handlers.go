package operations

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Deps is process-level metadata that is not stored in the snapshot.
type Deps struct {
	Build BuildMeta
}

// BuildMeta is linker-injected identity. Empty fields become conservative defaults.
type BuildMeta struct {
	Version   string
	Commit    string
	BuildTime string
	UIVersion string
}

func implementedHandlers(deps Deps) map[string]handleFunc {
	return map[string]handleFunc{
		IDSystemStatusGet: handleStatus,
		IDSystemBuildGet:  handleBuild(deps.Build),
		IDPolicyEvaluate:  handleEvaluate,
	}
}

func stubHandler(id string) handleFunc {
	return func(context.Context, *state.Snapshot, Input) (any, error) {
		return nil, domain.NewError(domain.CodeUnavailable, "operation is not implemented").
			WithDetail("operation", id)
	}
}

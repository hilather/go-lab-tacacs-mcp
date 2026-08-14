package operations

import (
	"context"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// Deps is process-level metadata that is not stored in the snapshot.
type Deps struct {
	Build        BuildMeta
	State        *state.Manager
	Entropy      io.Reader
	Sessions     SessionService
	Usage        TokenUsage
	Events       *events.Ring
	LoadBaseline func() (*config.Document, error)
	Secrets      config.SecretLookup
	Creds        *credentials.Service
	// Runtime is the live listener inventory. handleStatus does not use
	// it yet; HTTP/status still lists the three named sockets.
	Runtime StatusProvider
}

// StatusProvider is the live listener inventory from internal/runtime.
// Status handlers do not consult it yet.
type StatusProvider interface {
	Ready() bool
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
		IDSystemStatusGet:    handleStatus,
		IDSystemBuildGet:     handleBuild(deps.Build),
		IDConfigEffectiveGet: handleEffectiveConfig,
		IDConfigValidate:     handleValidateConfig(deps),
		IDConfigReload:       handleReloadConfig(deps),
		IDConfigExport:       handleExportConfig(deps),
		IDRuntimeReset:       handleResetRuntime(deps),
		IDUsersList:          handleUsersList,
		IDUsersGet:           handleUsersGet,
		IDUsersCreate:        handleUsersCreate(deps),
		IDUsersUpdate:        handleUsersUpdate(deps),
		IDUsersDelete:        handleUsersDelete(deps),
		IDGroupsList:         handleGroupsList,
		IDGroupsGet:          handleGroupsGet,
		IDGroupsCreate:       handleGroupsCreate(deps),
		IDGroupsUpdate:       handleGroupsUpdate(deps),
		IDGroupsDelete:       handleGroupsDelete(deps),
		IDClientsList:        handleClientsList,
		IDClientsGet:         handleClientsGet,
		IDClientsCreate:      handleClientsCreate(deps),
		IDClientsUpdate:      handleClientsUpdate(deps),
		IDClientsDelete:      handleClientsDelete(deps),
		IDTokensList:         handleTokensList(deps),
		IDTokensCreate:       handleTokensCreate(deps),
		IDTokensRevoke:       handleTokensRevoke(deps),
		IDSessionCreate:      handleSessionCreate(deps),
		IDSessionDelete:      handleSessionDelete(deps),
		IDPolicyEvaluate:     handleEvaluate,
		IDAuthenticationTest: handleAuthenticationTest(deps),
		IDEventsList:         handleListEvents(deps.Events),
		IDEventsSubscribe:    handleSubscribe,
	}
}

func stubHandler(id string) handleFunc {
	return func(context.Context, *state.Snapshot, Input) (any, error) {
		return nil, domain.NewError(domain.CodeUnavailable, "operation is not implemented").
			WithDetail("operation", id)
	}
}

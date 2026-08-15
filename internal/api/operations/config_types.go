package operations

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Config views accepted by effective.get and export.
const (
	ConfigViewEffective = "effective"
	ConfigViewBaseline  = "baseline"
	ConfigViewOverlay   = "overlay"
)

// GetEffectiveConfigRequest selects which redacted view to return.
type GetEffectiveConfigRequest struct {
	View string `json:"view,omitempty"`
}

// EffectiveConfig is the redacted JSON view of configuration objects.
type EffectiveConfig struct {
	Revision               domain.Revision `json:"revision"`
	View                   string          `json:"view"`
	BaselineHash           string          `json:"baseline_hash"`
	OverlayHash            string          `json:"overlay_hash"`
	CompiledAt             time.Time       `json:"compiled_at"`
	InstanceID             string          `json:"instance_id"`
	SourceSchemaVersion    int             `json:"source_schema_version"`
	EffectiveSchemaVersion int             `json:"effective_schema_version"`
	Users                  []User          `json:"users"`
	Groups                 []Group         `json:"groups"`
	Clients                []Client        `json:"clients"`
	Tokens                 []TokenView     `json:"tokens"`
	Warnings               []string        `json:"warnings,omitempty"`
}

func (e EffectiveConfig) envelopeRevision() domain.Revision { return e.Revision }

// ValidateConfigRequest validates a candidate YAML document or the mounted source.
// Empty YAML validates the mounted baseline when LoadBaseline is configured.
type ValidateConfigRequest struct {
	YAML string `json:"yaml,omitempty"`
}

// ValidateConfigResult is a preview. It never publishes state.
type ValidateConfigResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationIssue `json:"errors,omitempty"`
}

// ValidationIssue is one machine-readable validation failure.
type ValidationIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// ReloadConfigRequest reloads the mounted baseline. Body is empty.
type ReloadConfigRequest struct{}

// ReloadConfigResult is the published snapshot after a successful reload.
type ReloadConfigResult struct {
	Revision     domain.Revision `json:"revision"`
	BaselineHash string          `json:"baseline_hash"`
	OverlayHash  string          `json:"overlay_hash"`
}

func (r ReloadConfigResult) envelopeRevision() domain.Revision { return r.Revision }

// ExportConfigRequest selects which redacted YAML view to emit.
// Normalize is the explicit v1→v2 convert flag (KD-19). Default false:
// a v1 source still exports as v1-shaped YAML.
type ExportConfigRequest struct {
	View      string `json:"view,omitempty"`
	Normalize bool   `json:"normalize,omitempty"`
}

// ExportConfigResult is a redacted YAML document. Secret values are placeholders.
type ExportConfigResult struct {
	Revision               domain.Revision `json:"revision"`
	View                   string          `json:"view"`
	Format                 string          `json:"format"`
	YAML                   string          `json:"yaml"`
	SourceSchemaVersion    int             `json:"source_schema_version"`
	EffectiveSchemaVersion int             `json:"effective_schema_version"`
	Normalized             bool            `json:"normalized"`
}

func (e ExportConfigResult) envelopeRevision() domain.Revision { return e.Revision }

// ResetRuntimeRequest drops the overlay including tombstones.
type ResetRuntimeRequest struct{}

// ResetRuntimeResult is the published snapshot after reset.
type ResetRuntimeResult struct {
	Revision     domain.Revision `json:"revision"`
	BaselineHash string          `json:"baseline_hash"`
	OverlayHash  string          `json:"overlay_hash"`
}

func (r ResetRuntimeResult) envelopeRevision() domain.Revision { return r.Revision }

// TestAuthenticationRequest runs one authentication check against the snapshot.
// Password and Data are write-only and never appear in the result.
type TestAuthenticationRequest struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id,omitempty"`
	Method   string `json:"method"`
	Password string `json:"password,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

// AuthenticationTestResult is the redacted outcome. Status is pass, fail, error, or restart.
// *_configured flags are admin capability metadata from the snapshot, not a
// TACACS username-enumeration guarantee.
type AuthenticationTestResult struct {
	Status              string `json:"status"`
	Method              string `json:"method"`
	UserID              string `json:"user_id"`
	ClientID            string `json:"client_id,omitempty"`
	ASCIIPapConfigured  bool   `json:"ascii_pap_configured"`
	ChallengeConfigured bool   `json:"challenge_configured"`
	EnableConfigured    bool   `json:"enable_configured"`
}

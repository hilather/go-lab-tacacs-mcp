package operations

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"gopkg.in/yaml.v3"
)

func handleEffectiveConfig(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(GetEffectiveConfigRequest)
	view, err := normalizeConfigView(req.View)
	if err != nil {
		return nil, err
	}
	return buildEffective(snap, view), nil
}

func handleExportConfig(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
	if snap == nil {
		return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	req, _ := in.Request.(ExportConfigRequest)
	view, err := normalizeConfigView(req.View)
	if err != nil {
		return nil, err
	}
	eff := buildEffective(snap, view)
	raw, err := marshalExportYAML(eff)
	if err != nil {
		return nil, domain.NewError(domain.CodeInternal, "cannot encode export")
	}
	return ExportConfigResult{Revision: snap.Revision, View: view, Format: "yaml", YAML: string(raw)}, nil
}

func handleValidateConfig(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		req, _ := in.Request.(ValidateConfigRequest)
		doc, err := loadCandidate(deps, req)
		if err != nil {
			return validateFailure(err), nil
		}
		if err := config.Validate(doc); err != nil {
			return validateFailure(err), nil
		}
		if deps.State != nil {
			if err := deps.State.ValidateCandidate(doc); err != nil {
				return validateFailure(err), nil
			}
		}
		audit(deps, "api.config.validated", "ok", 0)
		return ValidateConfigResult{Valid: true}, nil
	}
}

func handleReloadConfig(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		if deps.LoadBaseline == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "mounted configuration source is not configured")
		}
		doc, err := deps.LoadBaseline()
		if err != nil {
			return nil, err
		}
		if err := config.Validate(doc); err != nil {
			return nil, err
		}
		published, err := deps.State.Reload(doc, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		audit(deps, "api.config.reloaded", "ok", published.Revision)
		return ReloadConfigResult{Revision: published.Revision, BaselineHash: published.BaselineHash, OverlayHash: published.OverlayHash}, nil
	}
}

func handleResetRuntime(deps Deps) handleFunc {
	return func(_ context.Context, _ *state.Snapshot, in Input) (any, error) {
		if err := requireState(deps); err != nil {
			return nil, err
		}
		published, err := deps.State.Reset(in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		audit(deps, "api.runtime.reset", "ok", published.Revision)
		return ResetRuntimeResult{Revision: published.Revision, BaselineHash: published.BaselineHash, OverlayHash: published.OverlayHash}, nil
	}
}

func loadCandidate(deps Deps, req ValidateConfigRequest) (*config.Document, error) {
	yamlText := strings.TrimSpace(req.YAML)
	if yamlText != "" {
		return config.Parse([]byte(yamlText))
	}
	if deps.LoadBaseline == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "yaml is required when no mounted source is configured").WithPath("yaml")
	}
	return deps.LoadBaseline()
}

func validateFailure(err error) ValidateConfigResult {
	issue := ValidationIssue{Code: string(domain.CodeInvalidArgument), Message: err.Error()}
	if de, ok := domain.AsError(err); ok {
		issue.Code = string(de.Code)
		issue.Message = de.Message
		issue.Path = de.Path
	}
	return ValidateConfigResult{Valid: false, Errors: []ValidationIssue{issue}}
}

func normalizeConfigView(view string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(view)) {
	case "", ConfigViewEffective:
		return ConfigViewEffective, nil
	case ConfigViewBaseline:
		return ConfigViewBaseline, nil
	case ConfigViewOverlay:
		return ConfigViewOverlay, nil
	default:
		return "", domain.NewError(domain.CodeInvalidArgument, "view must be effective, baseline, or overlay").WithPath("view")
	}
}

func buildEffective(snap *state.Snapshot, view string) EffectiveConfig {
	out := EffectiveConfig{
		Revision:     snap.Revision,
		View:         view,
		BaselineHash: snap.BaselineHash,
		OverlayHash:  snap.OverlayHash,
		CompiledAt:   snap.CompiledAt,
		Users:        []User{},
		Groups:       []Group{},
		Clients:      []Client{},
		Tokens:       []TokenView{},
	}
	if settings := snap.Settings(); settings != nil {
		out.InstanceID = settings.Server.InstanceID
	}
	switch view {
	case ConfigViewBaseline:
		out.Users, out.Groups, out.Clients = baselineObjects(snap)
	case ConfigViewOverlay:
		for _, u := range snap.Users() {
			if u.Meta.Source == domain.SourceRuntime || u.Meta.Source == domain.SourceOverride {
				out.Users = append(out.Users, userView(u, snap.Revision))
			}
		}
		for _, g := range snap.Groups() {
			if g.Meta.Source == domain.SourceRuntime || g.Meta.Source == domain.SourceOverride {
				out.Groups = append(out.Groups, groupView(g, snap.Revision))
			}
		}
		for _, c := range snap.Clients() {
			if c.Meta.Source == domain.SourceRuntime || c.Meta.Source == domain.SourceOverride {
				out.Clients = append(out.Clients, clientView(c, snap.Revision))
			}
		}
		for _, t := range snap.Tokens() {
			if t.Meta.Source == domain.SourceRuntime || t.Meta.Source == domain.SourceOverride {
				out.Tokens = append(out.Tokens, tokenView(t, nil))
			}
		}
		for _, t := range snap.Tombstones() {
			switch t.Kind {
			case domain.KindUser:
				out.Users = append(out.Users, deletedUser(t, snap.Revision))
			case domain.KindGroup:
				out.Groups = append(out.Groups, deletedGroup(t, snap.Revision))
			case domain.KindClient:
				out.Clients = append(out.Clients, deletedClient(t, snap.Revision))
			}
		}
	default:
		for _, u := range snap.Users() {
			out.Users = append(out.Users, userView(u, snap.Revision))
		}
		for _, g := range snap.Groups() {
			out.Groups = append(out.Groups, groupView(g, snap.Revision))
		}
		for _, c := range snap.Clients() {
			out.Clients = append(out.Clients, clientView(c, snap.Revision))
		}
		for _, t := range snap.Tokens() {
			out.Tokens = append(out.Tokens, tokenView(t, nil))
		}
		out.Warnings = snap.Warnings()
	}
	return out
}

func baselineObjects(snap *state.Snapshot) ([]User, []Group, []Client) {
	settings := snap.Settings()
	if settings == nil {
		return []User{}, []Group{}, []Client{}
	}
	users := make([]User, 0, len(settings.Users))
	for _, u := range settings.Users {
		if live, ok := snap.User(u.ID); ok && live.Meta.Source == domain.SourceConfig {
			users = append(users, userView(live, snap.Revision))
			continue
		}
		users = append(users, User{
			ID:                  u.ID,
			DisplayName:         u.DisplayName,
			Enabled:             u.Enabled,
			Source:              domain.SourceConfig,
			EffectiveRevision:   snap.Revision,
			Labels:              cloneLabels(u.Labels),
			GroupIDs:            cloneStrings(u.GroupIDs),
			Rules:               ruleSetView(u.Rules),
			Restrictions:        restrictionsView(u.Restrictions),
			ASCIIPapConfigured:  u.Credentials.Login.Verifier.Set(),
			ChallengeConfigured: u.Credentials.Challenge.Secret.Set(),
			EnableConfigured:    u.Credentials.Enable.Verifier.Set(),
		})
	}
	groups := make([]Group, 0, len(settings.Groups))
	for _, g := range settings.Groups {
		if live, ok := snap.Group(g.ID); ok && live.Meta.Source == domain.SourceConfig {
			groups = append(groups, groupView(live, snap.Revision))
			continue
		}
		action := string(g.DefaultCommandAction)
		if action == string(domain.DecisionDeny) {
			action = ""
		}
		groups = append(groups, Group{
			ID:                   g.ID,
			DisplayName:          g.DisplayName,
			Enabled:              g.Enabled,
			Priority:             g.Priority,
			Source:               domain.SourceConfig,
			EffectiveRevision:    snap.Revision,
			Labels:               cloneLabels(g.Labels),
			Services:             serviceViews(g.Services),
			CommandRules:         commandViews(g.CommandRules),
			DefaultCommandAction: action,
		})
	}
	clients := make([]Client, 0, len(settings.Clients))
	for _, c := range settings.Clients {
		if live, ok := snap.Client(c.ID); ok && live.Meta.Source == domain.SourceConfig {
			clients = append(clients, clientView(live, snap.Revision))
			continue
		}
		clients = append(clients, Client{
			ID:                     c.ID,
			DisplayName:            c.DisplayName,
			Enabled:                c.Enabled,
			Priority:               c.Priority,
			Source:                 domain.SourceConfig,
			EffectiveRevision:      snap.Revision,
			Labels:                 cloneLabels(c.Labels),
			Match:                  clientMatchView(c.Match),
			SharedSecretConfigured: c.Legacy.SharedSecret.Set(),
			SharedSecretLifecycle:  string(domain.LifecycleUnknown),
			Authentication:         clientAuthView(c.Authentication),
			Authorization:          clientAuthzView(c.Authorization),
			Accounting:             clientAcctView(c.Accounting),
		})
	}
	return users, groups, clients
}

type exportDoc struct {
	SchemaVersion int            `yaml:"schema_version"`
	View          string         `yaml:"view"`
	Revision      uint64         `yaml:"revision"`
	InstanceID    string         `yaml:"instance_id,omitempty"`
	Users         []exportUser   `yaml:"users"`
	Groups        []exportGroup  `yaml:"groups"`
	Clients       []exportClient `yaml:"clients"`
	Tokens        []exportToken  `yaml:"tokens,omitempty"`
}

type exportUser struct {
	ID                  string            `yaml:"id"`
	DisplayName         string            `yaml:"display_name,omitempty"`
	Enabled             bool              `yaml:"enabled"`
	Source              string            `yaml:"source"`
	Deleted             bool              `yaml:"deleted,omitempty"`
	GroupIDs            []string          `yaml:"group_ids,omitempty"`
	Labels              map[string]string `yaml:"labels,omitempty"`
	ASCIIPapConfigured  bool              `yaml:"ascii_pap_configured"`
	ChallengeConfigured bool              `yaml:"challenge_configured"`
	EnableConfigured    bool              `yaml:"enable_configured"`
	Login               exportSecret      `yaml:"credentials_login,omitempty"`
	Challenge           exportSecret      `yaml:"credentials_challenge,omitempty"`
	Enable              exportSecret      `yaml:"credentials_enable,omitempty"`
}

type exportGroup struct {
	ID           string            `yaml:"id"`
	DisplayName  string            `yaml:"display_name,omitempty"`
	Enabled      bool              `yaml:"enabled"`
	Priority     int               `yaml:"priority"`
	Source       string            `yaml:"source"`
	Deleted      bool              `yaml:"deleted,omitempty"`
	Labels       map[string]string `yaml:"labels,omitempty"`
	Services     []ServiceRuleView `yaml:"services,omitempty"`
	CommandRules []CommandRuleView `yaml:"command_rules,omitempty"`
}

type exportClient struct {
	ID                     string            `yaml:"id"`
	DisplayName            string            `yaml:"display_name,omitempty"`
	Enabled                bool              `yaml:"enabled"`
	Priority               int               `yaml:"priority"`
	Source                 string            `yaml:"source"`
	Deleted                bool              `yaml:"deleted,omitempty"`
	Labels                 map[string]string `yaml:"labels,omitempty"`
	Match                  ClientMatchView   `yaml:"match"`
	SharedSecretConfigured bool              `yaml:"shared_secret_configured"`
	SharedSecretLifecycle  string            `yaml:"shared_secret_lifecycle"`
	SharedSecret           exportSecret      `yaml:"shared_secret,omitempty"`
	Authentication         ClientAuthView    `yaml:"authentication"`
	Authorization          ClientAuthzView   `yaml:"authorization"`
}

type exportToken struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name,omitempty"`
	Source  string   `yaml:"source"`
	Enabled bool     `yaml:"enabled"`
	Scopes  []string `yaml:"scopes"`
}

type exportSecret struct {
	Redacted bool   `yaml:"redacted"`
	Source   string `yaml:"source,omitempty"`
}

func marshalExportYAML(eff EffectiveConfig) ([]byte, error) {
	doc := exportDoc{
		SchemaVersion: config.SchemaVersion,
		View:          eff.View,
		Revision:      uint64(eff.Revision),
		InstanceID:    eff.InstanceID,
		Users:         make([]exportUser, 0, len(eff.Users)),
		Groups:        make([]exportGroup, 0, len(eff.Groups)),
		Clients:       make([]exportClient, 0, len(eff.Clients)),
	}
	for _, u := range eff.Users {
		eu := exportUser{
			ID: u.ID, DisplayName: u.DisplayName, Enabled: u.Enabled, Source: string(u.Source),
			Deleted: u.Deleted, GroupIDs: u.GroupIDs, Labels: u.Labels,
			ASCIIPapConfigured: u.ASCIIPapConfigured, ChallengeConfigured: u.ChallengeConfigured, EnableConfigured: u.EnableConfigured,
		}
		if u.ASCIIPapConfigured {
			eu.Login = exportSecret{Redacted: true, Source: "file"}
		}
		if u.ChallengeConfigured {
			eu.Challenge = exportSecret{Redacted: true, Source: "file"}
		}
		if u.EnableConfigured {
			eu.Enable = exportSecret{Redacted: true, Source: "file"}
		}
		doc.Users = append(doc.Users, eu)
	}
	for _, g := range eff.Groups {
		doc.Groups = append(doc.Groups, exportGroup{
			ID: g.ID, DisplayName: g.DisplayName, Enabled: g.Enabled, Priority: g.Priority,
			Source: string(g.Source), Deleted: g.Deleted, Labels: g.Labels,
			Services: g.Services, CommandRules: g.CommandRules,
		})
	}
	for _, c := range eff.Clients {
		ec := exportClient{
			ID: c.ID, DisplayName: c.DisplayName, Enabled: c.Enabled, Priority: c.Priority,
			Source: string(c.Source), Deleted: c.Deleted, Labels: c.Labels, Match: c.Match,
			SharedSecretConfigured: c.SharedSecretConfigured, SharedSecretLifecycle: c.SharedSecretLifecycle,
			Authentication: c.Authentication, Authorization: c.Authorization,
		}
		if c.SharedSecretConfigured {
			ec.SharedSecret = exportSecret{Redacted: true, Source: "file"}
		}
		doc.Clients = append(doc.Clients, ec)
	}
	for _, t := range eff.Tokens {
		doc.Tokens = append(doc.Tokens, exportToken{ID: t.ID, Name: t.Name, Source: string(t.Source), Enabled: t.Enabled, Scopes: t.Scopes})
	}
	return yaml.Marshal(doc)
}

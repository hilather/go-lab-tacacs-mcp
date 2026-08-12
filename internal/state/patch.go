package state

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"golang.org/x/text/secure/precis"
)

// SecretPatch is a typed credential update. A nil *SecretPatch means omit
// (retain the effective material). Clear is an explicit null.
type SecretPatch struct {
	Clear bool
	Ref   config.SecretRef
}

// UpdateUser is a typed user patch. Omitted pointer fields are left unchanged.
type UpdateUser struct {
	DisplayName  *string
	Enabled      *bool
	Labels       *map[string]string
	GroupIDs     *[]string
	Rules        *config.RuleSet
	Login        *SecretPatch
	Challenge    *SecretPatch
	Enable       *SecretPatch
	Restrictions *config.UserRestrictions
}

// CreateUser creates a runtime user or an explicit baseline override.
type CreateUser struct {
	ID           string
	DisplayName  *string
	Enabled      *bool
	Labels       *map[string]string
	GroupIDs     *[]string
	Rules        *config.RuleSet
	Login        *SecretPatch
	Challenge    *SecretPatch
	Enable       *SecretPatch
	Restrictions *config.UserRestrictions
	Override     bool
}

// UpdateGroup is a typed group patch.
type UpdateGroup struct {
	DisplayName          *string
	Enabled              *bool
	Priority             *int
	Labels               *map[string]string
	Services             *[]config.ServiceRule
	CommandRules         *[]config.CommandRule
	DefaultCommandAction *domain.AuthorDecision
}

// CreateGroup creates a runtime group or an explicit baseline override.
type CreateGroup struct {
	ID                   string
	DisplayName          *string
	Enabled              *bool
	Priority             *int
	Labels               *map[string]string
	Services             *[]config.ServiceRule
	CommandRules         *[]config.CommandRule
	DefaultCommandAction *domain.AuthorDecision
	Override             bool
}

// UpdateClient is a typed client patch.
type UpdateClient struct {
	DisplayName           *string
	Enabled               *bool
	Priority              *int
	Labels                *map[string]string
	Match                 *config.ClientMatch
	SharedSecret          *SecretPatch
	SharedSecretLifecycle *config.SecretLifecycleMeta
	Authentication        *config.ClientAuth
	Authorization         *config.ClientAuthz
	Accounting            *config.ClientAcct
}

// CreateClient creates a runtime client or an explicit baseline override.
type CreateClient struct {
	ID                    string
	DisplayName           *string
	Enabled               *bool
	Priority              *int
	Labels                *map[string]string
	Match                 *config.ClientMatch
	SharedSecret          *SecretPatch
	SharedSecretLifecycle *config.SecretLifecycleMeta
	Authentication        *config.ClientAuth
	Authorization         *config.ClientAuthz
	Accounting            *config.ClientAcct
	Override              bool
}

// CreateToken records a runtime token descriptor. Material is never stored.
type CreateToken struct {
	ID        string
	Name      string
	Scopes    []string
	Enabled   *bool
	ExpiresAt *time.Time
	Material  credentials.TokenMaterial
	Override  bool
}

// DeleteOptions controls tombstone vs reveal-baseline for override deletes.
type DeleteOptions struct {
	Tombstone bool
	ActorID   string
}

func applySecret(cur config.SecretRef, patch *SecretPatch, methodEnabled bool, path string) (config.SecretRef, error) {
	if patch == nil {
		return cur, nil
	}
	if patch.Clear || !patch.Ref.Set() {
		if methodEnabled {
			return config.SecretRef{}, domain.NewError(domain.CodeAuthMethodCredentialMissing, "enabled method is missing required credential material").WithPath(path)
		}
		return config.SecretRef{Purpose: cur.Purpose}, nil
	}
	out := patch.Ref
	if out.Purpose == "" {
		out.Purpose = cur.Purpose
	}
	return out, nil
}

func applyUserPatch(cur config.User, p UpdateUser) (config.User, error) {
	out := cloneUser(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.GroupIDs != nil {
		out.GroupIDs = cloneStrings(*p.GroupIDs)
	}
	if p.Rules != nil {
		out.Rules = cloneRuleSet(*p.Rules)
	}
	if p.Restrictions != nil {
		out.Restrictions.ClientIDs = cloneStrings(p.Restrictions.ClientIDs)
		out.Restrictions.ValidAfter = cloneTimePtr(p.Restrictions.ValidAfter)
		out.Restrictions.ValidBefore = cloneTimePtr(p.Restrictions.ValidBefore)
	}
	var err error
	// Login remains required while the user is an enabled login identity.
	// Challenge and ENABLE material are optional and may be cleared.
	if out.Credentials.Login.Verifier, err = applySecret(out.Credentials.Login.Verifier, p.Login, out.Enabled, "credentials.login.verifier"); err != nil {
		return config.User{}, err
	}
	if out.Credentials.Challenge.Secret, err = applySecret(out.Credentials.Challenge.Secret, p.Challenge, false, "credentials.challenge.secret"); err != nil {
		return config.User{}, err
	}
	if out.Credentials.Enable.Verifier, err = applySecret(out.Credentials.Enable.Verifier, p.Enable, false, "credentials.enable.verifier"); err != nil {
		return config.User{}, err
	}
	return out, nil
}

func applyGroupPatch(cur config.Group, p UpdateGroup) (config.Group, error) {
	out := cloneGroup(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Priority != nil {
		out.Priority = *p.Priority
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.Services != nil {
		out.Services = cloneServiceRules(*p.Services)
	}
	if p.CommandRules != nil {
		out.CommandRules = cloneCommandRules(*p.CommandRules)
	}
	if p.DefaultCommandAction != nil {
		out.DefaultCommandAction = *p.DefaultCommandAction
	}
	return out, nil
}

func applyClientPatch(cur config.Client, p UpdateClient) (config.Client, error) {
	out := cloneClient(cur)
	if p.DisplayName != nil {
		out.DisplayName = *p.DisplayName
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Priority != nil {
		out.Priority = *p.Priority
	}
	if p.Labels != nil {
		out.Labels = cloneLabels(*p.Labels)
	}
	if p.Match != nil {
		out.Match.SourceCIDRs = cloneStrings(p.Match.SourceCIDRs)
		out.Match.Transports = append([]domain.Transport(nil), p.Match.Transports...)
		out.Match.Mode = p.Match.Mode
		if out.Match.Mode == "" {
			out.Match.Mode = domain.MatchAddressAndCertificate
		}
		out.Match.Certificate.DNSSANs = cloneStrings(p.Match.Certificate.DNSSANs)
		out.Match.Certificate.IPSANs = cloneStrings(p.Match.Certificate.IPSANs)
	}
	if p.SharedSecretLifecycle != nil {
		out.Legacy.SharedSecretLifecycle.LastRotatedAt = cloneTimePtr(p.SharedSecretLifecycle.LastRotatedAt)
		out.Legacy.SharedSecretLifecycle.RotationInterval = p.SharedSecretLifecycle.RotationInterval
	}
	if p.Authentication != nil {
		out.Authentication.AllowedMethods = append([]config.AuthMethod(nil), p.Authentication.AllowedMethods...)
		out.Authentication.DefaultService = p.Authentication.DefaultService
	}
	if p.Authorization != nil {
		out.Authorization.DefaultGroupIDs = cloneStrings(p.Authorization.DefaultGroupIDs)
	}
	if p.Accounting != nil {
		out.Accounting = *p.Accounting
	}
	legacyOn := hasLegacyTransport(out.Match.Transports)
	var err error
	if out.Legacy.SharedSecret, err = applySecret(out.Legacy.SharedSecret, p.SharedSecret, legacyOn, "legacy.shared_secret"); err != nil {
		return config.Client{}, err
	}
	return out, nil
}

func hasLegacyTransport(ts []domain.Transport) bool {
	for _, t := range ts {
		if t == domain.TransportLegacy {
			return true
		}
	}
	return false
}

func userFromCreate(base *config.User, req CreateUser) (config.User, error) {
	var cur config.User
	if base != nil {
		cur = cloneUser(*base)
	} else {
		cur.Enabled = true
		cur.Credentials.Login.Verifier.Purpose = credentials.PurposeLoginVerifier
		cur.Credentials.Challenge.Secret.Purpose = credentials.PurposeChallengeSecret
		cur.Credentials.Enable.Verifier.Purpose = credentials.PurposeEnableVerifier
	}
	cur.ID = req.ID
	return applyUserPatch(cur, UpdateUser{
		DisplayName:  req.DisplayName,
		Enabled:      req.Enabled,
		Labels:       req.Labels,
		GroupIDs:     req.GroupIDs,
		Rules:        req.Rules,
		Login:        req.Login,
		Challenge:    req.Challenge,
		Enable:       req.Enable,
		Restrictions: req.Restrictions,
	})
}

func groupFromCreate(base *config.Group, req CreateGroup) (config.Group, error) {
	var cur config.Group
	if base != nil {
		cur = cloneGroup(*base)
	} else {
		cur.Enabled = true
		cur.DefaultCommandAction = domain.DecisionDeny
	}
	cur.ID = req.ID
	return applyGroupPatch(cur, UpdateGroup{
		DisplayName:          req.DisplayName,
		Enabled:              req.Enabled,
		Priority:             req.Priority,
		Labels:               req.Labels,
		Services:             req.Services,
		CommandRules:         req.CommandRules,
		DefaultCommandAction: req.DefaultCommandAction,
	})
}

func clientFromCreate(base *config.Client, req CreateClient) (config.Client, error) {
	var cur config.Client
	if base != nil {
		cur = cloneClient(*base)
	} else {
		cur.Enabled = true
		cur.Match.Mode = domain.MatchAddressAndCertificate
		cur.Legacy.SharedSecret.Purpose = credentials.PurposeLegacySharedSecret
		cur.Accounting.Enabled = true
		cur.Accounting.AcceptStart = true
		cur.Accounting.AcceptStop = true
		cur.Accounting.AcceptWatchdog = true
	}
	cur.ID = req.ID
	return applyClientPatch(cur, UpdateClient{
		DisplayName:           req.DisplayName,
		Enabled:               req.Enabled,
		Priority:              req.Priority,
		Labels:                req.Labels,
		Match:                 req.Match,
		SharedSecret:          req.SharedSecret,
		SharedSecretLifecycle: req.SharedSecretLifecycle,
		Authentication:        req.Authentication,
		Authorization:         req.Authorization,
		Accounting:            req.Accounting,
	})
}

func normalizeUserID(id string) (string, error) {
	if id == "" {
		return "", domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath("id")
	}
	out, err := precis.UsernameCasePreserved.String(id)
	if err != nil || out == "" {
		return "", domain.NewError(domain.CodeInvalidArgument, "id is not a valid UsernameCasePreserved identifier").WithPath("id")
	}
	return out, nil
}

func requireID(id, path string) error {
	if id == "" {
		return domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath(path)
	}
	return nil
}

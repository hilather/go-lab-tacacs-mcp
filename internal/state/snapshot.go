package state

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// CompiledCommand is a command rule with RE2 patterns compiled at snapshot time.
type CompiledCommand struct {
	Rule    config.CommandRule
	Command *regexp.Regexp
	Args    *regexp.Regexp
}

// CompiledRuleSet is the snapshot-time form of services + command_rules.
type CompiledRuleSet struct {
	Services []config.ServiceRule
	Commands []CompiledCommand
}

// Snapshot is an immutable compiled view. Callers must not mutate returned
// objects; methods return copies.
type Snapshot struct {
	Revision     domain.Revision
	BaselineHash string
	OverlayHash  string
	CompiledAt   time.Time

	settings      *config.Document
	users         map[string]EffectiveUser
	groups        map[string]EffectiveGroup
	clients       map[string]EffectiveClient
	tokens        map[string]EffectiveToken
	userIDs       []string
	groupIDs      []string
	clientIDs     []string
	tokenIDs      []string
	tokenIndex    map[tokenDigestKey]string
	tombstones    []domain.Tombstone
	fallback      config.RuleSet
	fallbackRules CompiledRuleSet
	index         *config.ClientIndex
	secretWarns   []config.SecretWarning
	matchWarnings []string
	lifecycles    map[string]domain.SecretLifecycle
}

// tokenDigestKey is a map key whose fmt output never includes digest bytes.
type tokenDigestKey struct {
	n [credentials.TokenDigestLength]byte
}

func (k tokenDigestKey) String() string { return "[redacted]" }

func (k tokenDigestKey) GoString() string { return "[redacted]" }

func (k tokenDigestKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[redacted]")
}

func tokenKey(d credentials.TokenDigest) tokenDigestKey {
	return tokenDigestKey{n: credentials.DigestIndex(d)}
}

// CredentialCapabilities is non-secret presence metadata for a user.
type CredentialCapabilities struct {
	Login     bool
	Challenge bool
	Enable    bool
}

// EffectiveUser is a complete user plus administrative metadata.
type EffectiveUser struct {
	Meta         domain.ObjectMeta
	User         config.User
	Rules        CompiledRuleSet
	Capabilities CredentialCapabilities
}

// EffectiveGroup is a complete group plus administrative metadata.
type EffectiveGroup struct {
	Meta  domain.ObjectMeta
	Group config.Group
	Rules CompiledRuleSet
}

// EffectiveClient is a complete client plus administrative metadata.
type EffectiveClient struct {
	Meta      domain.ObjectMeta
	Client    config.Client
	Lifecycle domain.SecretLifecycle
}

// EffectiveToken is a non-secret token descriptor.
type EffectiveToken struct {
	Meta      domain.ObjectMeta
	ID        string
	Name      string
	Scopes    []string
	Enabled   bool
	ExpiresAt *time.Time
	HasDigest bool
}

// Settings returns the compiled non-overlay baseline settings. The returned
// document must be treated as read-only.
func (s *Snapshot) Settings() *config.Document { return s.settings }

// FallbackRules returns the effective fallback rule set.
func (s *Snapshot) FallbackRules() config.RuleSet { return cloneRuleSet(s.fallback) }

// CompiledFallback returns snapshot-time fallback matchers.
func (s *Snapshot) CompiledFallback() CompiledRuleSet { return s.fallbackRules }

// User returns a copy of the effective user.
func (s *Snapshot) User(id string) (EffectiveUser, bool) {
	u, ok := s.users[id]
	if !ok {
		return EffectiveUser{}, false
	}
	return EffectiveUser{Meta: cloneMeta(u.Meta), User: cloneUser(u.User), Rules: u.Rules, Capabilities: u.Capabilities}, true
}

// Users returns enabled-and-disabled live users, sorted by id. Deleted
// identities are omitted.
func (s *Snapshot) Users() []EffectiveUser {
	out := make([]EffectiveUser, 0, len(s.userIDs))
	for _, id := range s.userIDs {
		if u, ok := s.User(id); ok {
			out = append(out, u)
		}
	}
	return out
}

// Group returns a copy of the effective group.
func (s *Snapshot) Group(id string) (EffectiveGroup, bool) {
	g, ok := s.groups[id]
	if !ok {
		return EffectiveGroup{}, false
	}
	return EffectiveGroup{Meta: cloneMeta(g.Meta), Group: cloneGroup(g.Group), Rules: g.Rules}, true
}

// Groups returns live groups sorted by id.
func (s *Snapshot) Groups() []EffectiveGroup {
	out := make([]EffectiveGroup, 0, len(s.groupIDs))
	for _, id := range s.groupIDs {
		if g, ok := s.Group(id); ok {
			out = append(out, g)
		}
	}
	return out
}

// Client returns a copy of the effective client.
func (s *Snapshot) Client(id string) (EffectiveClient, bool) {
	c, ok := s.clients[id]
	if !ok {
		return EffectiveClient{}, false
	}
	return EffectiveClient{
		Meta:      cloneMeta(c.Meta),
		Client:    cloneClient(c.Client),
		Lifecycle: c.Lifecycle,
	}, true
}

// Clients returns live clients sorted by id.
func (s *Snapshot) Clients() []EffectiveClient {
	out := make([]EffectiveClient, 0, len(s.clientIDs))
	for _, id := range s.clientIDs {
		if c, ok := s.Client(id); ok {
			out = append(out, c)
		}
	}
	return out
}

// Token returns a copy of the effective token descriptor.
func (s *Snapshot) Token(id string) (EffectiveToken, bool) {
	tok, ok := s.tokens[id]
	if !ok {
		return EffectiveToken{}, false
	}
	out := tok
	out.Meta = cloneMeta(tok.Meta)
	out.Scopes = cloneStrings(tok.Scopes)
	out.ExpiresAt = cloneTimePtr(tok.ExpiresAt)
	return out, true
}

// Tokens returns live token descriptors sorted by id.
func (s *Snapshot) Tokens() []EffectiveToken {
	out := make([]EffectiveToken, 0, len(s.tokenIDs))
	for _, id := range s.tokenIDs {
		if tok, ok := s.Token(id); ok {
			out = append(out, tok)
		}
	}
	return out
}

// AuthenticateToken looks up a presented bearer by SHA-256 digest. Failures
// share one unauthenticated error so callers cannot enumerate tokens.
func (s *Snapshot) AuthenticateToken(raw []byte, now time.Time) (EffectiveToken, error) {
	denied := domain.NewError(domain.CodeUnauthenticated, "authentication required")
	if s == nil || len(raw) == 0 {
		return EffectiveToken{}, denied
	}
	presented := credentials.DigestToken(credentials.NewTokenMaterial(raw))
	if s.tokenIndex == nil {
		return EffectiveToken{}, denied
	}
	id, ok := s.tokenIndex[tokenKey(presented)]
	if !ok {
		return EffectiveToken{}, denied
	}
	tok, ok := s.Token(id)
	if !ok || !tok.Enabled {
		return EffectiveToken{}, denied
	}
	if tok.ExpiresAt != nil && !now.Before(tok.ExpiresAt.UTC()) {
		return EffectiveToken{}, denied
	}
	return tok, nil
}

// Tombstones returns overlay deletions. They are not listed by Users/Groups/Clients.
func (s *Snapshot) Tombstones() []domain.Tombstone {
	if len(s.tombstones) == 0 {
		return nil
	}
	out := make([]domain.Tombstone, len(s.tombstones))
	copy(out, s.tombstones)
	return out
}

// Warnings returns compile diagnostics that did not fail publication.
func (s *Snapshot) Warnings() []string {
	n := len(s.matchWarnings) + len(s.secretWarns)
	if n == 0 {
		return nil
	}
	out := append([]string(nil), s.matchWarnings...)
	for _, w := range s.secretWarns {
		out = append(out, w.Path+": "+w.Message)
	}
	return out
}

// ClientIndex returns the compiled matcher. It is immutable.
func (s *Snapshot) ClientIndex() *config.ClientIndex { return s.index }

// MatchClient selects one client for a peer. Ties fail closed.
func (s *Snapshot) MatchClient(transport domain.Transport, ip net.IP, cert *config.CertIdentity) (EffectiveClient, error) {
	if s == nil || s.index == nil {
		return EffectiveClient{}, domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	id, err := s.index.Match(transport, ip, cert)
	if err != nil {
		return EffectiveClient{}, err
	}
	c, ok := s.Client(id)
	if !ok {
		return EffectiveClient{}, domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	return c, nil
}

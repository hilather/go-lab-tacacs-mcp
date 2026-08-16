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
	policyradius "github.com/hilather/go-lab-tacacs-mcp/internal/policy/radius"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
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

	settings             *config.Document
	users                map[string]EffectiveUser
	groups               map[string]EffectiveGroup
	clients              map[string]EffectiveClient
	tokens               map[string]EffectiveToken
	userIDs              []string
	groupIDs             []string
	clientIDs            []string
	tokenIDs             []string
	tokenIndex           map[tokenDigestKey]string
	tombstones           []domain.Tombstone
	fallback             config.RuleSet
	fallbackRules        CompiledRuleSet
	index                *config.ClientIndex
	radiusAccessIndex    *config.RADIUSIndex
	radiusAcctIndex      *config.RADIUSIndex
	radiusAccessTLSIndex *config.RADIUSCertIndex
	radiusAcctTLSIndex   *config.RADIUSCertIndex
	radiusPolicies       *policyradius.Engine
	radiusDictionary     Dictionary
	radiusDictVersion    string
	secretWarns          []config.SecretWarning
	matchWarnings        []string
	lifecycles           map[string]domain.SecretLifecycle
	runtimeSecrets       map[string][]byte
}

// Dictionary is the compiled RADIUS attribute dictionary attached to a
// snapshot. Version is exactly builtin-mvp-1 when no operator file compiled.
// Do not import radius/codec or radius/udp here.
type Dictionary struct {
	view attribute.Dictionary
}

// Version is the dictionary identifier, for example "builtin-mvp-1".
func (d Dictionary) Version() string { return d.view.Version() }

// Empty reports whether no dictionary is attached.
func (d Dictionary) Empty() bool { return d.view.Version() == "" }

// View is the compiled attribute dictionary used by radius.attributes.list.
func (d Dictionary) View() attribute.Dictionary { return d.view }

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
	Meta            domain.ObjectMeta
	Client          config.Client
	Lifecycle       domain.SecretLifecycle
	RADIUSLifecycle domain.SecretLifecycle
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

// RuntimeSecret copies in-process overlay material for id. Callers wipe the buffer.
func (s *Snapshot) RuntimeSecret(id string) ([]byte, bool) {
	if s == nil || id == "" {
		return nil, false
	}
	b, ok := s.runtimeSecrets[id]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

// LifecycleCounts is the number of live clients in each secret-lifecycle
// status. Status is the only dimension — no client IDs.
func (s *Snapshot) LifecycleCounts() map[domain.SecretLifecycle]int {
	out := map[domain.SecretLifecycle]int{
		domain.LifecycleCurrent: 0,
		domain.LifecycleDueSoon: 0,
		domain.LifecycleOverdue: 0,
		domain.LifecycleUnknown: 0,
	}
	if s == nil {
		return out
	}
	for _, st := range s.lifecycles {
		if !st.Valid() {
			st = domain.LifecycleUnknown
		}
		out[st]++
	}
	return out
}

// SecretWarnings returns compiled shared-secret diagnostics (overdue, reuse).
// Copies so callers cannot mutate the snapshot.
func (s *Snapshot) SecretWarnings() []config.SecretWarning {
	if s == nil || len(s.secretWarns) == 0 {
		return nil
	}
	out := make([]config.SecretWarning, len(s.secretWarns))
	copy(out, s.secretWarns)
	return out
}

// SecretWarningCount is the number of compiled secret warnings.
func (s *Snapshot) SecretWarningCount() int {
	if s == nil {
		return 0
	}
	return len(s.secretWarns)
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
		Meta:            cloneMeta(c.Meta),
		Client:          cloneClient(c.Client),
		Lifecycle:       c.Lifecycle,
		RADIUSLifecycle: c.RADIUSLifecycle,
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

// ClientIndex returns the compiled TACACS matcher. It is immutable.
func (s *Snapshot) ClientIndex() *config.ClientIndex { return s.index }

// RADIUSAccessIndex returns the compiled RADIUS access LPM. It is immutable.
func (s *Snapshot) RADIUSAccessIndex() *config.RADIUSIndex {
	if s == nil {
		return nil
	}
	return s.radiusAccessIndex
}

// RADIUSAccountingIndex returns the compiled RADIUS accounting LPM. It is immutable.
func (s *Snapshot) RADIUSAccountingIndex() *config.RADIUSIndex {
	if s == nil {
		return nil
	}
	return s.radiusAcctIndex
}

// RADIUSAccessTLSIndex returns the compiled RADIUS TLS access cert index.
func (s *Snapshot) RADIUSAccessTLSIndex() *config.RADIUSCertIndex {
	if s == nil {
		return nil
	}
	return s.radiusAccessTLSIndex
}

// RADIUSAccountingTLSIndex returns the compiled RADIUS TLS accounting cert index.
func (s *Snapshot) RADIUSAccountingTLSIndex() *config.RADIUSCertIndex {
	if s == nil {
		return nil
	}
	return s.radiusAcctTLSIndex
}

// RADIUSPolicies returns the compiled RADIUS access-policy engine.
func (s *Snapshot) RADIUSPolicies() *policyradius.Engine {
	if s == nil {
		return nil
	}
	return s.radiusPolicies
}

// Dictionary returns the compiled RADIUS dictionary view.
func (s *Snapshot) Dictionary() Dictionary {
	if s == nil {
		return Dictionary{}
	}
	return s.radiusDictionary
}

// DictionaryVersion is the compiled dictionary identifier, or empty.
func (s *Snapshot) DictionaryVersion() string {
	if s == nil {
		return ""
	}
	return s.radiusDictVersion
}

// MatchRADIUS selects one client for a RADIUS role and carrier. UDP uses
// source-IP LPM. TLS uses MatchRADIUSTLS (cert required).
func (s *Snapshot) MatchRADIUS(role domain.ListenerRole, carrier domain.Carrier, ip net.IP) (client EffectiveClient, endpointID string, err error) {
	if s == nil {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	if carrier == domain.CarrierRADIUSTLS {
		return EffectiveClient{}, "", domain.NewError(domain.CodeInvalidArgument, "RADIUS TLS match requires a peer certificate").WithPath("clients")
	}
	var idx *config.RADIUSIndex
	switch role {
	case domain.RoleAccess:
		idx = s.radiusAccessIndex
	case domain.RoleAccounting:
		idx = s.radiusAcctIndex
	default:
		return EffectiveClient{}, "", domain.NewError(domain.CodeInvalidArgument, "RADIUS index role must be access or accounting")
	}
	if idx == nil {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	id, epid, err := idx.Match(ip)
	if err != nil {
		return EffectiveClient{}, "", err
	}
	c, ok := s.Client(id)
	if !ok {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	return c, epid, nil
}

// MatchRADIUSTLS selects one client for a RADIUS TLS role after handshake.
func (s *Snapshot) MatchRADIUSTLS(role domain.ListenerRole, ip net.IP, cert *config.CertIdentity) (client EffectiveClient, endpointID string, err error) {
	if s == nil {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	var idx *config.RADIUSCertIndex
	switch role {
	case domain.RoleAccess:
		idx = s.radiusAccessTLSIndex
	case domain.RoleAccounting:
		idx = s.radiusAcctTLSIndex
	default:
		return EffectiveClient{}, "", domain.NewError(domain.CodeInvalidArgument, "RADIUS cert index role must be access or accounting")
	}
	if idx == nil {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	id, epid, err := idx.Match(ip, cert)
	if err != nil {
		return EffectiveClient{}, "", err
	}
	c, ok := s.Client(id)
	if !ok {
		return EffectiveClient{}, "", domain.NewError(domain.CodeNotFound, "no client matches the peer").WithPath("clients")
	}
	return c, epid, nil
}

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

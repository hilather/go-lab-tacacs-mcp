package state

import (
	"crypto/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Manager owns baseline + overlay and publishes snapshots through an atomic pointer.
type Manager struct {
	mu       sync.Mutex
	baseline *config.Document
	overlay  overlay
	current  atomic.Pointer[Snapshot]
	revision atomic.Uint64
	clock    domain.Clock
	lookup   config.SecretLookup
	hmacKey  []byte
	born     map[string]identityStamp
	hook     func(*Snapshot)
}

// Options configure snapshot compilation. Secrets is optional; when nil, file
// contents are not resolved and shared-secret byte policy is skipped.
type Options struct {
	Clock   domain.Clock
	Secrets config.SecretLookup
	HMACKey []byte
	Hook    func(*Snapshot)
}

// New validates the baseline, compiles revision 1, and publishes it.
func New(baseline *config.Document, opts Options) (*Manager, error) {
	if baseline == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "baseline is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}
	key := append([]byte(nil), opts.HMACKey...)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, domain.NewError(domain.CodeInternal, "cannot initialize process-local key")
		}
	}
	m := &Manager{
		baseline: cloneDocument(baseline),
		overlay:  newOverlay(),
		clock:    clock,
		lookup:   opts.Secrets,
		hmacKey:  key,
		born:     map[string]identityStamp{},
		hook:     opts.Hook,
	}
	snap, born, err := m.compile(m.baseline, m.overlay, 1, clock.Now(), true)
	if err != nil {
		return nil, err
	}
	m.born = born
	m.revision.Store(1)
	m.current.Store(snap)
	return m, nil
}

// Snapshot returns the published snapshot. Readers do not take the write lock.
func (m *Manager) Snapshot() *Snapshot {
	if m == nil {
		return nil
	}
	return m.current.Load()
}

// Revision is the published snapshot revision.
func (m *Manager) Revision() domain.Revision {
	s := m.Snapshot()
	if s == nil {
		return 0
	}
	return s.Revision
}

// ValidateCandidate compiles newBaseline plus the current overlay without publishing.
func (m *Manager) ValidateCandidate(newBaseline *config.Document) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if newBaseline == nil {
		return domain.NewError(domain.CodeInvalidArgument, "baseline is required")
	}
	ov := copyOverlay(m.overlay)
	_, _, err := m.compile(cloneDocument(newBaseline), ov, domain.Revision(m.revision.Load()+1), m.clock.Now(), true)
	return err
}

// Reload replaces the baseline. Overlay is rebased or dropped per the new
// document's runtime.reload_overlay_behavior. Failure leaves the current snapshot.
func (m *Manager) Reload(newBaseline *config.Document, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if newBaseline == nil {
			return ov, nil, domain.NewError(domain.CodeInvalidArgument, "baseline is required")
		}
		next := cloneDocument(newBaseline)
		if next.Runtime.ReloadOverlayBehavior == "reset" {
			return newOverlay(), next, nil
		}
		return ov, next, nil
	})
}

// Reset drops the entire overlay including tombstones.
func (m *Manager) Reset(expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		return newOverlay(), nil, nil
	})
}

// CreateUser inserts a runtime user or an explicit baseline override.
func (m *Manager) CreateUser(req CreateUser, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		id, err := normalizeUserID(req.ID)
		if err != nil {
			return ov, nil, err
		}
		req.ID = id
		if _, live := liveUser(m.baseline, ov, id); live {
			if !req.Override {
				return ov, nil, domain.NewError(domain.CodeAlreadyExists, "user already exists").WithPath("users/" + id)
			}
			base, inBase := baselineUser(m.baseline, id)
			if !inBase {
				return ov, nil, domain.NewError(domain.CodeAlreadyExists, "user already exists").WithPath("users/" + id)
			}
			if !m.baseline.Runtime.AllowShadowing {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("users/" + id)
			}
			u, err := userFromCreate(&base, req)
			if err != nil {
				return ov, nil, err
			}
			var prev *domain.ObjectMeta
			if e, ok := ov.users[id]; ok && !e.deleted {
				prev = &e.meta
			}
			ov.users[id] = overlayUser{
				user: u,
				meta: newOverlayMeta(domain.KindUser, id, u.DisplayName, domain.SourceOverride, domain.SourceConfig, u.Enabled, u.Labels, rev, now, prev),
			}
			return ov, nil, nil
		}
		if _, inBase := baselineUser(m.baseline, id); inBase {
			if !req.Override {
				return ov, nil, domain.NewError(domain.CodeAlreadyExists, "user already exists").WithPath("users/" + id)
			}
			if !m.baseline.Runtime.AllowShadowing {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("users/" + id)
			}
			base, _ := baselineUser(m.baseline, id)
			u, err := userFromCreate(&base, req)
			if err != nil {
				return ov, nil, err
			}
			ov.users[id] = overlayUser{
				user: u,
				meta: newOverlayMeta(domain.KindUser, id, u.DisplayName, domain.SourceOverride, domain.SourceConfig, u.Enabled, u.Labels, rev, now, nil),
			}
			return ov, nil, nil
		}
		u, err := userFromCreate(nil, req)
		if err != nil {
			return ov, nil, err
		}
		ov.users[id] = overlayUser{
			user: u,
			meta: newOverlayMeta(domain.KindUser, id, u.DisplayName, domain.SourceRuntime, "", u.Enabled, u.Labels, rev, now, nil),
		}
		return ov, nil, nil
	})
}

// UpdateUser applies a typed patch to the current effective user.
func (m *Manager) UpdateUser(id string, patch UpdateUser, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		id, err := normalizeUserID(id)
		if err != nil {
			return ov, nil, err
		}
		cur, ok := liveUser(m.baseline, ov, id)
		if !ok {
			return ov, nil, domain.NewError(domain.CodeNotFound, "user not found").WithPath("users/" + id)
		}
		_, inBase := baselineUser(m.baseline, id)
		if inBase && !m.baseline.Runtime.AllowShadowing {
			if e, ok := ov.users[id]; !ok || e.deleted {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("users/" + id)
			}
		}
		next, err := applyUserPatch(cur, patch)
		if err != nil {
			return ov, nil, err
		}
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.users[id]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.users[id] = overlayUser{
			user: next,
			meta: newOverlayMeta(domain.KindUser, id, next.DisplayName, src, shadows, next.Enabled, next.Labels, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// DeleteUser tombstones a baseline identity, removes a runtime identity, or
// reveals the baseline when deleting an override without Tombstone.
func (m *Manager) DeleteUser(id string, opts DeleteOptions, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		id, err := normalizeUserID(id)
		if err != nil {
			return ov, nil, err
		}
		_, inBase := baselineUser(m.baseline, id)
		e, inOv := ov.users[id]
		live := false
		if inOv && !e.deleted {
			live = true
		} else if !inOv && inBase {
			live = true
		}
		if !live {
			return ov, nil, domain.NewError(domain.CodeNotFound, "user not found").WithPath("users/" + id)
		}
		if inOv && !e.deleted && e.meta.Source == domain.SourceRuntime {
			delete(ov.users, id)
			return ov, nil, nil
		}
		if inOv && !e.deleted && e.meta.Source == domain.SourceOverride && !opts.Tombstone {
			delete(ov.users, id)
			return ov, nil, nil
		}
		if !inBase {
			delete(ov.users, id)
			return ov, nil, nil
		}
		ov.users[id] = overlayUser{
			deleted:   true,
			tombstone: domain.NewTombstone(domain.KindUser, domain.ObjectID(id), opts.ActorID, rev, now),
			meta: domain.ObjectMeta{
				ID:              domain.ObjectID(id),
				Kind:            domain.KindUser,
				Source:          domain.SourceConfig,
				Deleted:         true,
				RevisionCreated: rev,
				RevisionUpdated: rev,
				UpdatedAt:       now,
				CreatedAt:       now,
			},
		}
		return ov, nil, nil
	})
}

// CreateGroup inserts a runtime group or an explicit baseline override.
func (m *Manager) CreateGroup(req CreateGroup, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(req.ID, "id"); err != nil {
			return ov, nil, err
		}
		if _, live := liveGroup(m.baseline, ov, req.ID); live && !req.Override {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "group already exists").WithPath("groups/" + req.ID)
		}
		base, inBase := baselineGroup(m.baseline, req.ID)
		var basePtr *config.Group
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			if !req.Override {
				return ov, nil, domain.NewError(domain.CodeAlreadyExists, "group already exists").WithPath("groups/" + req.ID)
			}
			if !m.baseline.Runtime.AllowShadowing {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("groups/" + req.ID)
			}
			basePtr = &base
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		} else if _, ok := liveGroup(m.baseline, ov, req.ID); ok {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "group already exists").WithPath("groups/" + req.ID)
		}
		g, err := groupFromCreate(basePtr, req)
		if err != nil {
			return ov, nil, err
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.groups[req.ID]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.groups[req.ID] = overlayGroup{
			group: g,
			meta:  newOverlayMeta(domain.KindGroup, req.ID, g.DisplayName, src, shadows, g.Enabled, g.Labels, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// UpdateGroup applies a typed patch to the current effective group.
func (m *Manager) UpdateGroup(id string, patch UpdateGroup, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(id, "id"); err != nil {
			return ov, nil, err
		}
		cur, ok := liveGroup(m.baseline, ov, id)
		if !ok {
			return ov, nil, domain.NewError(domain.CodeNotFound, "group not found").WithPath("groups/" + id)
		}
		_, inBase := baselineGroup(m.baseline, id)
		if inBase && !m.baseline.Runtime.AllowShadowing {
			if e, ok := ov.groups[id]; !ok || e.deleted {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("groups/" + id)
			}
		}
		next, err := applyGroupPatch(cur, patch)
		if err != nil {
			return ov, nil, err
		}
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.groups[id]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.groups[id] = overlayGroup{
			group: next,
			meta:  newOverlayMeta(domain.KindGroup, id, next.DisplayName, src, shadows, next.Enabled, next.Labels, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// DeleteGroup mirrors DeleteUser for groups.
func (m *Manager) DeleteGroup(id string, opts DeleteOptions, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(id, "id"); err != nil {
			return ov, nil, err
		}
		_, inBase := baselineGroup(m.baseline, id)
		e, inOv := ov.groups[id]
		live := (inOv && !e.deleted) || (!inOv && inBase)
		if !live {
			return ov, nil, domain.NewError(domain.CodeNotFound, "group not found").WithPath("groups/" + id)
		}
		if inOv && !e.deleted && (e.meta.Source == domain.SourceRuntime || (e.meta.Source == domain.SourceOverride && !opts.Tombstone)) {
			delete(ov.groups, id)
			return ov, nil, nil
		}
		if !inBase {
			delete(ov.groups, id)
			return ov, nil, nil
		}
		ov.groups[id] = overlayGroup{
			deleted:   true,
			tombstone: domain.NewTombstone(domain.KindGroup, domain.ObjectID(id), opts.ActorID, rev, now),
			meta:      domain.ObjectMeta{ID: domain.ObjectID(id), Kind: domain.KindGroup, Source: domain.SourceConfig, Deleted: true, RevisionUpdated: rev, UpdatedAt: now},
		}
		return ov, nil, nil
	})
}

// CreateClient inserts a runtime client or an explicit baseline override.
func (m *Manager) CreateClient(req CreateClient, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(req.ID, "id"); err != nil {
			return ov, nil, err
		}
		if _, live := liveClient(m.baseline, ov, req.ID); live && !req.Override {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "client already exists").WithPath("clients/" + req.ID)
		}
		base, inBase := baselineClient(m.baseline, req.ID)
		var basePtr *config.Client
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			if !req.Override {
				return ov, nil, domain.NewError(domain.CodeAlreadyExists, "client already exists").WithPath("clients/" + req.ID)
			}
			if !m.baseline.Runtime.AllowShadowing {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("clients/" + req.ID)
			}
			basePtr = &base
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		} else if _, ok := liveClient(m.baseline, ov, req.ID); ok {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "client already exists").WithPath("clients/" + req.ID)
		}
		c, err := clientFromCreate(basePtr, req)
		if err != nil {
			return ov, nil, err
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.clients[req.ID]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.clients[req.ID] = overlayClient{
			client: c,
			meta:   newOverlayMeta(domain.KindClient, req.ID, c.DisplayName, src, shadows, c.Enabled, c.Labels, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// UpdateClient applies a typed patch to the current effective client.
func (m *Manager) UpdateClient(id string, patch UpdateClient, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(id, "id"); err != nil {
			return ov, nil, err
		}
		cur, ok := liveClient(m.baseline, ov, id)
		if !ok {
			return ov, nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("clients/" + id)
		}
		_, inBase := baselineClient(m.baseline, id)
		if inBase && !m.baseline.Runtime.AllowShadowing {
			if e, ok := ov.clients[id]; !ok || e.deleted {
				return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("clients/" + id)
			}
		}
		next, err := applyClientPatch(cur, patch)
		if err != nil {
			return ov, nil, err
		}
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.clients[id]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.clients[id] = overlayClient{
			client: next,
			meta:   newOverlayMeta(domain.KindClient, id, next.DisplayName, src, shadows, next.Enabled, next.Labels, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// DeleteClient mirrors DeleteUser for clients.
func (m *Manager) DeleteClient(id string, opts DeleteOptions, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(id, "id"); err != nil {
			return ov, nil, err
		}
		_, inBase := baselineClient(m.baseline, id)
		e, inOv := ov.clients[id]
		live := (inOv && !e.deleted) || (!inOv && inBase)
		if !live {
			return ov, nil, domain.NewError(domain.CodeNotFound, "client not found").WithPath("clients/" + id)
		}
		if inOv && !e.deleted && (e.meta.Source == domain.SourceRuntime || (e.meta.Source == domain.SourceOverride && !opts.Tombstone)) {
			delete(ov.clients, id)
			return ov, nil, nil
		}
		if !inBase {
			delete(ov.clients, id)
			return ov, nil, nil
		}
		ov.clients[id] = overlayClient{
			deleted:   true,
			tombstone: domain.NewTombstone(domain.KindClient, domain.ObjectID(id), opts.ActorID, rev, now),
			meta:      domain.ObjectMeta{ID: domain.ObjectID(id), Kind: domain.KindClient, Source: domain.SourceConfig, Deleted: true, RevisionUpdated: rev, UpdatedAt: now},
		}
		return ov, nil, nil
	})
}

// CreateToken inserts a runtime token descriptor. Material is not retained.
func (m *Manager) CreateToken(req CreateToken, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(req.ID, "id"); err != nil {
			return ov, nil, err
		}
		for i, s := range req.Scopes {
			if !config.ValidScope(s) {
				return ov, nil, domain.NewError(domain.CodeInvalidArgument, "unknown scope").WithPath("scopes[" + strconv.Itoa(i) + "]")
			}
		}
		if len(req.Scopes) == 0 {
			return ov, nil, domain.NewError(domain.CodeInvalidArgument, "at least one scope is required").WithPath("scopes")
		}
		if _, ok := liveToken(m.baseline, ov, req.ID); ok && !req.Override {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "token already exists").WithPath("tokens/" + req.ID)
		}
		_, inBase := baselineToken(m.baseline, req.ID)
		if inBase && !req.Override {
			return ov, nil, domain.NewError(domain.CodeAlreadyExists, "token already exists").WithPath("tokens/" + req.ID)
		}
		if inBase && !m.baseline.Runtime.AllowShadowing {
			return ov, nil, domain.NewError(domain.CodeConflict, "shadowing is disabled").WithPath("tokens/" + req.ID)
		}
		src := domain.SourceRuntime
		var shadows domain.ObjectSource
		if inBase {
			src = domain.SourceOverride
			shadows = domain.SourceConfig
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		var dig credentials.TokenDigest
		if !req.Material.Empty() {
			dig = credentials.DigestToken(req.Material)
		}
		var prev *domain.ObjectMeta
		if e, ok := ov.tokens[req.ID]; ok && !e.deleted {
			prev = &e.meta
		}
		ov.tokens[req.ID] = overlayToken{
			token: tokenRecord{
				ID:        req.ID,
				Name:      req.Name,
				Scopes:    cloneStrings(req.Scopes),
				Enabled:   enabled,
				ExpiresAt: cloneTimePtr(req.ExpiresAt),
				HasDigest: !dig.Empty(),
				Digest:    dig,
			},
			meta: newOverlayMeta(domain.KindToken, req.ID, req.Name, src, shadows, enabled, nil, rev, now, prev),
		}
		return ov, nil, nil
	})
}

// DeleteToken removes a runtime token or tombstones a baseline token.
func (m *Manager) DeleteToken(id string, opts DeleteOptions, expected *domain.Revision) (*Snapshot, error) {
	return m.mutate(expected, func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error) {
		if err := requireID(id, "id"); err != nil {
			return ov, nil, err
		}
		_, inBase := baselineToken(m.baseline, id)
		e, inOv := ov.tokens[id]
		live := (inOv && !e.deleted) || (!inOv && inBase)
		if !live {
			return ov, nil, domain.NewError(domain.CodeNotFound, "token not found").WithPath("tokens/" + id)
		}
		if inOv && !e.deleted && (e.meta.Source == domain.SourceRuntime || (e.meta.Source == domain.SourceOverride && !opts.Tombstone)) {
			delete(ov.tokens, id)
			return ov, nil, nil
		}
		if !inBase {
			delete(ov.tokens, id)
			return ov, nil, nil
		}
		ov.tokens[id] = overlayToken{
			deleted:   true,
			tombstone: domain.NewTombstone(domain.KindToken, domain.ObjectID(id), opts.ActorID, rev, now),
			meta:      domain.ObjectMeta{ID: domain.ObjectID(id), Kind: domain.KindToken, Source: domain.SourceConfig, Deleted: true, RevisionUpdated: rev, UpdatedAt: now},
		}
		return ov, nil, nil
	})
}

func (m *Manager) mutate(expected *domain.Revision, fn func(ov overlay, now time.Time, rev domain.Revision) (overlay, *config.Document, error)) (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.revision.Load()
	if err := checkRevision(expected, domain.Revision(cur)); err != nil {
		return nil, err
	}
	now := m.clock.Now()
	nextRev := domain.Revision(cur + 1)
	ov := copyOverlay(m.overlay)
	ov, newBase, err := fn(ov, now, nextRev)
	if err != nil {
		return nil, err
	}
	base := m.baseline
	if newBase != nil {
		base = newBase
	}
	snap, born, err := m.compile(base, ov, nextRev, now, newBase != nil)
	if err != nil {
		return nil, err
	}
	if newBase != nil {
		m.baseline = newBase
	}
	m.overlay = ov
	m.born = born
	m.revision.Store(uint64(nextRev))
	m.current.Store(snap)
	if m.hook != nil {
		m.hook(snap)
	}
	return snap, nil
}

func checkRevision(expected *domain.Revision, actual domain.Revision) error {
	if expected == nil {
		return nil
	}
	if *expected != actual {
		return domain.NewError(domain.CodeRevisionMismatch, "expected revision does not match published snapshot").
			WithDetail("expected", *expected).
			WithDetail("actual", actual)
	}
	return nil
}

func liveUser(base *config.Document, ov overlay, id string) (config.User, bool) {
	if e, ok := ov.users[id]; ok {
		if e.deleted {
			return config.User{}, false
		}
		return cloneUser(e.user), true
	}
	return baselineUser(base, id)
}

func liveGroup(base *config.Document, ov overlay, id string) (config.Group, bool) {
	if e, ok := ov.groups[id]; ok {
		if e.deleted {
			return config.Group{}, false
		}
		return cloneGroup(e.group), true
	}
	return baselineGroup(base, id)
}

func liveClient(base *config.Document, ov overlay, id string) (config.Client, bool) {
	if e, ok := ov.clients[id]; ok {
		if e.deleted {
			return config.Client{}, false
		}
		return cloneClient(e.client), true
	}
	return baselineClient(base, id)
}

func liveToken(base *config.Document, ov overlay, id string) (tokenRecord, bool) {
	if e, ok := ov.tokens[id]; ok {
		if e.deleted {
			return tokenRecord{}, false
		}
		return e.token, true
	}
	if tok, ok := baselineToken(base, id); ok {
		return tokenRecord{ID: tok.ID, Name: tok.ID, Scopes: cloneStrings(tok.Scopes), Enabled: true, ExpiresAt: cloneTimePtr(tok.ExpiresAt), HasDigest: tok.Token.Set()}, true
	}
	return tokenRecord{}, false
}

package state

import (
	"regexp"
	"sort"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

type identityStamp struct {
	created    time.Time
	createdRev domain.Revision
	updated    time.Time
	updatedRev domain.Revision
}

func copyStamps(in map[string]identityStamp) map[string]identityStamp {
	out := make(map[string]identityStamp, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (m *Manager) compile(base *config.Document, ov overlay, rev domain.Revision, now time.Time, touchBaseline bool) (*Snapshot, map[string]identityStamp, error) {
	born := copyStamps(m.born)
	if touchBaseline {
		touchBaselineStamps(born, base, rev, now)
	}
	users, userTombs := mergeUsers(base, ov, rev, now, born)
	groups, groupTombs := mergeGroups(base, ov, rev, now, born)
	clients, clientTombs := mergeClients(base, ov, rev, now, born)
	tokens, tokenTombs, tokenDigests := mergeTokens(base, ov, rev, now, born)

	fallback := cloneRuleSet(base.FallbackRules)
	if ov.fallback != nil {
		fallback = cloneRuleSet(*ov.fallback)
	}

	synth := cloneDocument(base)
	synth.Users = make([]config.User, 0, len(users))
	for _, u := range users {
		synth.Users = append(synth.Users, cloneUser(u.User))
	}
	synth.Groups = make([]config.Group, 0, len(groups))
	for _, g := range groups {
		synth.Groups = append(synth.Groups, cloneGroup(g.Group))
	}
	synth.Clients = make([]config.Client, 0, len(clients))
	for _, c := range clients {
		synth.Clients = append(synth.Clients, cloneClient(c.Client))
	}
	synth.FallbackRules = fallback
	liveTokenIDs := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		liveTokenIDs[tok.ID] = struct{}{}
	}
	// Validate still sees baseline file-ref tokens; drop tombstoned IDs so the
	// cap is the merged live set, not baseline+overlay.
	kept := synth.API.BootstrapTokens[:0]
	for _, tok := range synth.API.BootstrapTokens {
		if _, ok := liveTokenIDs[tok.ID]; ok {
			kept = append(kept, tok)
		}
	}
	synth.API.BootstrapTokens = kept
	if cap := synth.Runtime.MaxObjects.APITokens; cap > 0 && len(tokens) > cap {
		return nil, nil, domain.NewError(domain.CodeObjectLimitExceeded, "token count exceeds configured maximum").WithPath("tokens")
	}

	if err := config.Validate(synth); err != nil {
		return nil, nil, err
	}
	idx, err := config.CompileClientIndex(synth.Clients)
	if err != nil {
		return nil, nil, err
	}

	var life map[string]domain.SecretLifecycle
	var sw []config.SecretWarning
	if m.lookup != nil {
		life, sw, err = config.EvaluateSecrets(synth, m.lookup, now, m.hmacKey)
		if err != nil {
			return nil, nil, err
		}
	}

	fbCompiled, err := compileRuleSet(fallback)
	if err != nil {
		return nil, nil, err
	}
	snap := &Snapshot{
		Revision:      rev,
		BaselineHash:  hashBaseline(base),
		OverlayHash:   hashOverlay(ov),
		CompiledAt:    now,
		settings:      cloneDocument(base),
		users:         map[string]EffectiveUser{},
		groups:        map[string]EffectiveGroup{},
		clients:       map[string]EffectiveClient{},
		tokens:        map[string]EffectiveToken{},
		tokenIndex:    map[tokenDigestKey]string{},
		fallback:      fallback,
		fallbackRules: fbCompiled,
		index:         idx,
		secretWarns:   sw,
		matchWarnings: idx.Warnings(),
		lifecycles:    life,
	}
	for _, u := range users {
		u.Meta.EffectiveRevision = rev
		compiled, err := compileRuleSet(u.User.Rules)
		if err != nil {
			return nil, nil, err
		}
		u.Rules = compiled
		u.Capabilities = CredentialCapabilities{
			Login:     u.User.Credentials.Login.Verifier.Set(),
			Challenge: u.User.Credentials.Challenge.Secret.Set(),
			Enable:    u.User.Credentials.Enable.Verifier.Set(),
		}
		snap.users[u.User.ID] = u
		snap.userIDs = append(snap.userIDs, u.User.ID)
	}
	for _, g := range groups {
		g.Meta.EffectiveRevision = rev
		compiled, err := compileRuleSet(config.RuleSet{Services: g.Group.Services, CommandRules: g.Group.CommandRules})
		if err != nil {
			return nil, nil, err
		}
		g.Rules = compiled
		snap.groups[g.Group.ID] = g
		snap.groupIDs = append(snap.groupIDs, g.Group.ID)
	}
	for _, c := range clients {
		c.Meta.EffectiveRevision = rev
		if life != nil {
			if st, ok := life[c.Client.ID]; ok {
				c.Lifecycle = st
			}
		}
		if c.Lifecycle == "" {
			c.Lifecycle = domain.LifecycleUnknown
		}
		snap.clients[c.Client.ID] = c
		snap.clientIDs = append(snap.clientIDs, c.Client.ID)
	}
	if err := indexTokenDigests(snap, base, tokens, tokenDigests, m.lookup); err != nil {
		return nil, nil, err
	}
	for _, tok := range tokens {
		tok.Meta.EffectiveRevision = rev
		snap.tokens[tok.ID] = tok
		snap.tokenIDs = append(snap.tokenIDs, tok.ID)
	}
	sort.Strings(snap.userIDs)
	sort.Strings(snap.groupIDs)
	sort.Strings(snap.clientIDs)
	sort.Strings(snap.tokenIDs)
	snap.tombstones = append(snap.tombstones, userTombs...)
	snap.tombstones = append(snap.tombstones, groupTombs...)
	snap.tombstones = append(snap.tombstones, clientTombs...)
	snap.tombstones = append(snap.tombstones, tokenTombs...)
	used := make(map[string]struct{}, len(snap.users)+len(snap.groups)+len(snap.clients)+len(snap.tokens)+len(base.Users)+len(base.Groups)+len(base.Clients)+len(base.API.BootstrapTokens))
	for _, u := range base.Users {
		used[string(domain.KindUser)+"/"+u.ID] = struct{}{}
	}
	for _, g := range base.Groups {
		used[string(domain.KindGroup)+"/"+g.ID] = struct{}{}
	}
	for _, c := range base.Clients {
		used[string(domain.KindClient)+"/"+c.ID] = struct{}{}
	}
	for _, tok := range base.API.BootstrapTokens {
		used[string(domain.KindToken)+"/"+tok.ID] = struct{}{}
	}
	for id := range snap.users {
		used[string(domain.KindUser)+"/"+id] = struct{}{}
	}
	for id := range snap.groups {
		used[string(domain.KindGroup)+"/"+id] = struct{}{}
	}
	for id := range snap.clients {
		used[string(domain.KindClient)+"/"+id] = struct{}{}
	}
	for id := range snap.tokens {
		used[string(domain.KindToken)+"/"+id] = struct{}{}
	}
	for k := range born {
		if _, ok := used[k]; !ok {
			delete(born, k)
		}
	}
	return snap, born, nil
}

func mergeUsers(base *config.Document, ov overlay, rev domain.Revision, now time.Time, born map[string]identityStamp) ([]EffectiveUser, []domain.Tombstone) {
	var out []EffectiveUser
	var tombs []domain.Tombstone
	seen := map[string]struct{}{}
	for _, u := range base.Users {
		seen[u.ID] = struct{}{}
		if e, ok := ov.users[u.ID]; ok {
			if e.deleted {
				tombs = append(tombs, e.tombstone)
				continue
			}
			meta := cloneMeta(e.meta)
			meta.EffectiveRevision = rev
			out = append(out, EffectiveUser{Meta: meta, User: cloneUser(e.user)})
			continue
		}
		out = append(out, EffectiveUser{
			Meta: configMeta(domain.KindUser, u.ID, u.DisplayName, u.Enabled, u.Labels, rev, now, born),
			User: cloneUser(u),
		})
	}
	ids := make([]string, 0, len(ov.users))
	for id := range ov.users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		e := ov.users[id]
		if e.deleted {
			tombs = append(tombs, e.tombstone)
			continue
		}
		meta := cloneMeta(e.meta)
		meta.EffectiveRevision = rev
		out = append(out, EffectiveUser{Meta: meta, User: cloneUser(e.user)})
	}
	return out, tombs
}

func mergeGroups(base *config.Document, ov overlay, rev domain.Revision, now time.Time, born map[string]identityStamp) ([]EffectiveGroup, []domain.Tombstone) {
	var out []EffectiveGroup
	var tombs []domain.Tombstone
	seen := map[string]struct{}{}
	for _, g := range base.Groups {
		seen[g.ID] = struct{}{}
		if e, ok := ov.groups[g.ID]; ok {
			if e.deleted {
				tombs = append(tombs, e.tombstone)
				continue
			}
			meta := cloneMeta(e.meta)
			meta.EffectiveRevision = rev
			out = append(out, EffectiveGroup{Meta: meta, Group: cloneGroup(e.group)})
			continue
		}
		out = append(out, EffectiveGroup{
			Meta:  configMeta(domain.KindGroup, g.ID, g.DisplayName, g.Enabled, g.Labels, rev, now, born),
			Group: cloneGroup(g),
		})
	}
	ids := make([]string, 0, len(ov.groups))
	for id := range ov.groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		e := ov.groups[id]
		if e.deleted {
			tombs = append(tombs, e.tombstone)
			continue
		}
		meta := cloneMeta(e.meta)
		meta.EffectiveRevision = rev
		out = append(out, EffectiveGroup{Meta: meta, Group: cloneGroup(e.group)})
	}
	return out, tombs
}

func mergeClients(base *config.Document, ov overlay, rev domain.Revision, now time.Time, born map[string]identityStamp) ([]EffectiveClient, []domain.Tombstone) {
	var out []EffectiveClient
	var tombs []domain.Tombstone
	seen := map[string]struct{}{}
	for _, c := range base.Clients {
		seen[c.ID] = struct{}{}
		if e, ok := ov.clients[c.ID]; ok {
			if e.deleted {
				tombs = append(tombs, e.tombstone)
				continue
			}
			meta := cloneMeta(e.meta)
			meta.EffectiveRevision = rev
			out = append(out, EffectiveClient{Meta: meta, Client: cloneClient(e.client)})
			continue
		}
		out = append(out, EffectiveClient{
			Meta:   configMeta(domain.KindClient, c.ID, c.DisplayName, c.Enabled, c.Labels, rev, now, born),
			Client: cloneClient(c),
		})
	}
	ids := make([]string, 0, len(ov.clients))
	for id := range ov.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		e := ov.clients[id]
		if e.deleted {
			tombs = append(tombs, e.tombstone)
			continue
		}
		meta := cloneMeta(e.meta)
		meta.EffectiveRevision = rev
		out = append(out, EffectiveClient{Meta: meta, Client: cloneClient(e.client)})
	}
	return out, tombs
}

func mergeTokens(base *config.Document, ov overlay, rev domain.Revision, now time.Time, born map[string]identityStamp) ([]EffectiveToken, []domain.Tombstone, map[string]credentials.TokenDigest) {
	var out []EffectiveToken
	var tombs []domain.Tombstone
	digests := map[string]credentials.TokenDigest{}
	seen := map[string]struct{}{}
	for _, tok := range base.API.BootstrapTokens {
		seen[tok.ID] = struct{}{}
		if e, ok := ov.tokens[tok.ID]; ok {
			if e.deleted {
				tombs = append(tombs, e.tombstone)
				continue
			}
			meta := cloneMeta(e.meta)
			meta.EffectiveRevision = rev
			out = append(out, tokenFromRecord(e.token, meta))
			if !e.token.Digest.Empty() {
				digests[tok.ID] = credentials.NewTokenDigest(e.token.Digest.Bytes())
			}
			continue
		}
		out = append(out, EffectiveToken{
			Meta:      configMeta(domain.KindToken, tok.ID, "", true, nil, rev, now, born),
			ID:        tok.ID,
			Name:      tok.ID,
			Scopes:    cloneStrings(tok.Scopes),
			Enabled:   true,
			ExpiresAt: cloneTimePtr(tok.ExpiresAt),
			HasDigest: tok.Token.Set(),
		})
	}
	ids := make([]string, 0, len(ov.tokens))
	for id := range ov.tokens {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		e := ov.tokens[id]
		if e.deleted {
			tombs = append(tombs, e.tombstone)
			continue
		}
		meta := cloneMeta(e.meta)
		meta.EffectiveRevision = rev
		out = append(out, tokenFromRecord(e.token, meta))
		if !e.token.Digest.Empty() {
			digests[id] = credentials.NewTokenDigest(e.token.Digest.Bytes())
		}
	}
	return out, tombs, digests
}

func indexTokenDigests(snap *Snapshot, base *config.Document, tokens []EffectiveToken, overlay map[string]credentials.TokenDigest, lookup config.SecretLookup) error {
	if snap.tokenIndex == nil {
		snap.tokenIndex = map[tokenDigestKey]string{}
	}
	live := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		live[tok.ID] = struct{}{}
	}
	for id, d := range overlay {
		if _, ok := live[id]; !ok || d.Empty() {
			continue
		}
		snap.tokenIndex[tokenKey(d)] = id
	}
	if lookup == nil {
		return nil
	}
	for _, boot := range base.API.BootstrapTokens {
		if _, ok := live[boot.ID]; !ok {
			continue
		}
		if _, have := overlay[boot.ID]; have {
			continue
		}
		if !boot.Token.Set() {
			continue
		}
		raw, err := lookup(boot.Token)
		if err != nil {
			return err
		}
		mat := credentials.NewTokenMaterial(raw)
		wipeBytes(raw)
		d := credentials.DigestToken(mat)
		mat.Wipe()
		if d.Empty() {
			continue
		}
		snap.tokenIndex[tokenKey(d)] = boot.ID
	}
	return nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func tokenFromRecord(t tokenRecord, meta domain.ObjectMeta) EffectiveToken {
	return EffectiveToken{
		Meta:      meta,
		ID:        t.ID,
		Name:      t.Name,
		Scopes:    cloneStrings(t.Scopes),
		Enabled:   t.Enabled,
		ExpiresAt: cloneTimePtr(t.ExpiresAt),
		HasDigest: t.HasDigest,
	}
}

func compileRuleSet(rs config.RuleSet) (CompiledRuleSet, error) {
	out := CompiledRuleSet{Services: cloneServiceRules(rs.Services)}
	for _, r := range rs.CommandRules {
		cc := CompiledCommand{Rule: r}
		if r.Command.Pattern != "" {
			re, err := regexp.Compile(r.Command.Pattern)
			if err != nil {
				return CompiledRuleSet{}, domain.NewError(domain.CodeRegexInvalid, "invalid regular expression").WithPath("command.pattern")
			}
			cc.Command = re
		}
		if r.Arguments.Pattern != "" {
			re, err := regexp.Compile(r.Arguments.Pattern)
			if err != nil {
				return CompiledRuleSet{}, domain.NewError(domain.CodeRegexInvalid, "invalid regular expression").WithPath("arguments.pattern")
			}
			cc.Args = re
		}
		out.Commands = append(out.Commands, cc)
	}
	return out, nil
}

func touchBaselineStamps(born map[string]identityStamp, base *config.Document, rev domain.Revision, now time.Time) {
	touch := func(kind domain.ObjectKind, id string) {
		key := string(kind) + "/" + id
		st, ok := born[key]
		if !ok {
			return
		}
		st.updated = now
		st.updatedRev = rev
		born[key] = st
	}
	for _, u := range base.Users {
		touch(domain.KindUser, u.ID)
	}
	for _, g := range base.Groups {
		touch(domain.KindGroup, g.ID)
	}
	for _, c := range base.Clients {
		touch(domain.KindClient, c.ID)
	}
	for _, tok := range base.API.BootstrapTokens {
		touch(domain.KindToken, tok.ID)
	}
}

func configMeta(kind domain.ObjectKind, id, display string, enabled bool, labels map[string]string, rev domain.Revision, now time.Time, born map[string]identityStamp) domain.ObjectMeta {
	key := string(kind) + "/" + id
	st, ok := born[key]
	if !ok {
		st = identityStamp{created: now, createdRev: rev, updated: now, updatedRev: rev}
		born[key] = st
	}
	return domain.ObjectMeta{
		ID:                domain.ObjectID(id),
		Kind:              kind,
		DisplayName:       display,
		Source:            domain.SourceConfig,
		Enabled:           enabled,
		Labels:            cloneLabels(labels),
		RevisionCreated:   st.createdRev,
		RevisionUpdated:   st.updatedRev,
		EffectiveRevision: rev,
		CreatedAt:         st.created,
		UpdatedAt:         st.updated,
	}
}

func newOverlayMeta(kind domain.ObjectKind, id, display string, source, shadows domain.ObjectSource, enabled bool, labels map[string]string, rev domain.Revision, now time.Time, prev *domain.ObjectMeta) domain.ObjectMeta {
	created := now
	createdRev := rev
	if prev != nil && prev.RevisionCreated != 0 {
		created = prev.CreatedAt
		createdRev = prev.RevisionCreated
	}
	return domain.ObjectMeta{
		ID:                domain.ObjectID(id),
		Kind:              kind,
		DisplayName:       display,
		Source:            source,
		ShadowsSource:     shadows,
		Enabled:           enabled,
		Labels:            cloneLabels(labels),
		RevisionCreated:   createdRev,
		RevisionUpdated:   rev,
		EffectiveRevision: rev,
		CreatedAt:         created,
		UpdatedAt:         now,
	}
}

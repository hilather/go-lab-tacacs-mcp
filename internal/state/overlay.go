package state

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

type overlay struct {
	users    map[string]overlayUser
	groups   map[string]overlayGroup
	clients  map[string]overlayClient
	tokens   map[string]overlayToken
	fallback *config.RuleSet
}

type overlayUser struct {
	deleted   bool
	tombstone domain.Tombstone
	user      config.User
	meta      domain.ObjectMeta
}

type overlayGroup struct {
	deleted   bool
	tombstone domain.Tombstone
	group     config.Group
	meta      domain.ObjectMeta
}

type overlayClient struct {
	deleted   bool
	tombstone domain.Tombstone
	client    config.Client
	meta      domain.ObjectMeta
}

type tokenRecord struct {
	ID        string
	Name      string
	Scopes    []string
	Enabled   bool
	ExpiresAt *time.Time
	HasDigest bool
	Digest    credentials.TokenDigest
}

type overlayToken struct {
	deleted   bool
	tombstone domain.Tombstone
	token     tokenRecord
	meta      domain.ObjectMeta
}

func newOverlay() overlay {
	return overlay{
		users:   map[string]overlayUser{},
		groups:  map[string]overlayGroup{},
		clients: map[string]overlayClient{},
		tokens:  map[string]overlayToken{},
	}
}

func copyOverlay(in overlay) overlay {
	out := overlay{
		users:   make(map[string]overlayUser, len(in.users)),
		groups:  make(map[string]overlayGroup, len(in.groups)),
		clients: make(map[string]overlayClient, len(in.clients)),
		tokens:  make(map[string]overlayToken, len(in.tokens)),
	}
	for k, v := range in.users {
		e := v
		if !v.deleted {
			e.user = cloneUser(v.user)
		}
		e.meta = cloneMeta(v.meta)
		out.users[k] = e
	}
	for k, v := range in.groups {
		e := v
		if !v.deleted {
			e.group = cloneGroup(v.group)
		}
		e.meta = cloneMeta(v.meta)
		out.groups[k] = e
	}
	for k, v := range in.clients {
		e := v
		if !v.deleted {
			e.client = cloneClient(v.client)
		}
		e.meta = cloneMeta(v.meta)
		out.clients[k] = e
	}
	for k, v := range in.tokens {
		e := v
		if !v.deleted {
			e.token.Scopes = cloneStrings(v.token.Scopes)
			e.token.ExpiresAt = cloneTimePtr(v.token.ExpiresAt)
			if !v.token.Digest.Empty() {
				e.token.Digest = credentials.NewTokenDigest(v.token.Digest.Bytes())
			}
		}
		e.meta = cloneMeta(v.meta)
		out.tokens[k] = e
	}
	if in.fallback != nil {
		fb := cloneRuleSet(*in.fallback)
		out.fallback = &fb
	}
	return out
}

func baselineUser(doc *config.Document, id string) (config.User, bool) {
	for _, u := range doc.Users {
		if u.ID == id {
			return u, true
		}
	}
	return config.User{}, false
}

func baselineGroup(doc *config.Document, id string) (config.Group, bool) {
	for _, g := range doc.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return config.Group{}, false
}

func baselineClient(doc *config.Document, id string) (config.Client, bool) {
	for _, c := range doc.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return config.Client{}, false
}

func baselineToken(doc *config.Document, id string) (config.BootstrapToken, bool) {
	for _, t := range doc.API.BootstrapTokens {
		if t.ID == id {
			return t, true
		}
	}
	return config.BootstrapToken{}, false
}

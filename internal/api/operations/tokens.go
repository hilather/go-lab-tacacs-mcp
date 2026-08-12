package operations

import (
	"context"
	"crypto/rand"
	"io"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

const (
	defaultTokenPage = 100
	maxTokenPage     = 500
)

func handleTokensList(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		req, _ := in.Request.(ListTokensRequest)
		limit := req.Limit
		if limit <= 0 {
			limit = defaultTokenPage
		}
		if limit > maxTokenPage {
			limit = maxTokenPage
		}
		all := snap.Tokens()
		start := 0
		if req.Cursor != "" {
			start = len(all)
			for i, tok := range all {
				if tok.ID > req.Cursor {
					start = i
					break
				}
			}
		}
		end := start + limit
		if end > len(all) {
			end = len(all)
		}
		page := all[start:end]
		items := make([]TokenView, 0, len(page))
		for _, tok := range page {
			items = append(items, tokenView(tok, deps.Usage))
		}
		var next *string
		if end < len(all) {
			c := all[end-1].ID
			next = &c
		}
		return TokenList{Revision: snap.Revision, Items: items, NextCursor: next}, nil
	}
}

func handleTokensCreate(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.State == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "token store is not configured")
		}
		req, _ := in.Request.(CreateTokenRequest)
		if len(req.Scopes) == 0 {
			return nil, domain.NewError(domain.CodeInvalidArgument, "at least one scope is required").WithPath("scopes")
		}
		for i, s := range req.Scopes {
			if !config.ValidScope(s) {
				return nil, domain.NewError(domain.CodeInvalidArgument, "unknown scope").WithPath("scopes").WithDetail("index", i)
			}
		}
		ent := deps.Entropy
		if ent == nil {
			ent = rand.Reader
		}
		value, _, err := credentials.IssueBearer(ent)
		if err != nil {
			return nil, domain.NewError(domain.CodeInternal, "cannot generate token")
		}
		mat := credentials.NewTokenMaterial([]byte(value))
		id := req.ID
		if id == "" {
			id, err = newTokenID(ent)
			if err != nil {
				mat.Wipe()
				return nil, domain.NewError(domain.CodeInternal, "cannot generate token id")
			}
		}
		name := req.Name
		if name == "" {
			name = id
		}
		published, err := deps.State.CreateToken(state.CreateToken{
			ID:        id,
			Name:      name,
			Scopes:    append([]string(nil), req.Scopes...),
			ExpiresAt: req.ExpiresAt,
			Material:  mat,
			Override:  req.Override,
		}, in.ExpectedRevision)
		mat.Wipe()
		if err != nil {
			return nil, err
		}
		tok, ok := published.Token(id)
		if !ok {
			return nil, domain.NewError(domain.CodeInternal, "created token is missing from snapshot")
		}
		view := tokenView(tok, deps.Usage)
		return CreatedToken{TokenView: view, Token: value, Revision: published.Revision}, nil
	}
}

func handleTokensRevoke(deps Deps) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, in Input) (any, error) {
		if deps.State == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "token store is not configured")
		}
		req, _ := in.Request.(RevokeTokenRequest)
		if req.ID == "" {
			return nil, domain.NewError(domain.CodeInvalidArgument, "id is required").WithPath("id")
		}
		published, err := deps.State.DeleteToken(req.ID, state.DeleteOptions{
			Tombstone: req.Tombstone,
			ActorID:   in.Actor.ID,
		}, in.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		return DeleteResult{ID: req.ID, Revision: published.Revision}, nil
	}
}

func tokenView(tok state.EffectiveToken, usage TokenUsage) TokenView {
	v := TokenView{
		ID:                tok.ID,
		Name:              tok.Name,
		Scopes:            append([]string(nil), tok.Scopes...),
		Enabled:           tok.Enabled,
		ExpiresAt:         tok.ExpiresAt,
		Source:            tok.Meta.Source,
		ShadowsSource:     tok.Meta.ShadowsSource,
		Deleted:           tok.Meta.Deleted,
		EffectiveRevision: tok.Meta.EffectiveRevision,
		CreatedAt:         tok.Meta.CreatedAt,
		UpdatedAt:         tok.Meta.UpdatedAt,
	}
	if usage != nil {
		if ts, ok := usage.LastUsed(tok.ID); ok {
			t := ts
			v.LastUsedAt = &t
		}
	}
	return v
}

func newTokenID(entropy io.Reader) (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(entropy, b); err != nil {
		return "", err
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 16)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out), nil
}

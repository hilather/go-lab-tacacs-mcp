package operations

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// ListTokensRequest lists API token descriptors.
type ListTokensRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// CreateTokenRequest creates a runtime token. The bearer is generated server-side.
type CreateTokenRequest struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Override  bool       `json:"override,omitempty"`
}

// RevokeTokenRequest deletes a runtime token or tombstones a baseline token.
type RevokeTokenRequest struct {
	ID        string `json:"id"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// TokenView is the secret-free descriptor returned by list.
type TokenView struct {
	ID                string              `json:"id"`
	Name              string              `json:"name,omitempty"`
	Scopes            []string            `json:"scopes"`
	Enabled           bool                `json:"enabled"`
	ExpiresAt         *time.Time          `json:"expires_at,omitempty"`
	Source            domain.ObjectSource `json:"source"`
	ShadowsSource     domain.ObjectSource `json:"shadows_source,omitempty"`
	Deleted           bool                `json:"deleted,omitempty"`
	EffectiveRevision domain.Revision     `json:"effective_revision"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	LastUsedAt        *time.Time          `json:"last_used_at,omitempty"`
}

// TokenList is tokens.list output in id order.
type TokenList struct {
	Revision   domain.Revision `json:"revision"`
	Items      []TokenView     `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

func (t TokenList) envelopeRevision() domain.Revision { return t.Revision }

// CreatedToken is the one-time create response. Token is the bearer value.
type CreatedToken struct {
	TokenView
	Token    string          `json:"token"`
	Revision domain.Revision `json:"revision"`
}

func (t CreatedToken) envelopeRevision() domain.Revision { return t.Revision }

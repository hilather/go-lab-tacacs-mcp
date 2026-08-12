package operations

import (
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// CreateSessionRequest exchanges an already-authenticated actor for a UI session.
type CreateSessionRequest struct{}

// DeleteSessionRequest ends one UI session. SessionID is filled from the cookie.
type DeleteSessionRequest struct {
	SessionID string `json:"session_id,omitempty"`
}

// Session is the REST_ONLY UI session view. Cookie is never JSON-encoded.
type Session struct {
	TokenID      string                    `json:"token_id"`
	Scopes       []string                  `json:"scopes"`
	ExpiresAt    time.Time                 `json:"expires_at"`
	CSRFToken    string                    `json:"csrf_token"`
	CookieName   string                    `json:"cookie_name"`
	CookieSecure bool                      `json:"cookie_secure"`
	SameSite     string                    `json:"same_site"`
	CookiePath   string                    `json:"cookie_path"`
	CookieMaxAge int                       `json:"cookie_max_age"`
	Revision     domain.Revision           `json:"revision"`
	Cookie       credentials.SessionCookie `json:"-"`
}

func (s Session) envelopeRevision() domain.Revision { return s.Revision }

// SessionService issues and revokes UI sessions. Implemented by api/auth.
type SessionService interface {
	Create(actor Actor, snap *state.Snapshot) (Session, error)
	Delete(sessionID string) (DeleteResult, error)
}

// TokenUsage is optional coarse last-used tracking.
type TokenUsage interface {
	LastUsed(id string) (time.Time, bool)
	Forget(id string)
}

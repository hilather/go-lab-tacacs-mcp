package auth

import (
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Principal is an authenticated actor. Scopes are exact-match only.
type Principal struct {
	ID     string
	Scopes []string
}

// Actor converts p to the operation-registry actor type.
func (p Principal) Actor() operations.Actor {
	return operations.Actor{ID: p.ID, Scopes: append([]string(nil), p.Scopes...)}
}

// Verifier looks up bootstrap token digests. It is safe for concurrent use.
type Verifier struct {
	mu    sync.RWMutex
	clock domain.Clock
	by    map[[credentials.TokenDigestLength]byte]entry
}

type entry struct {
	id        string
	scopes    []string
	expiresAt *time.Time
}

// Load resolves bootstrap tokens from doc using lookup.
func Load(doc *config.Document, lookup config.SecretLookup, clock domain.Clock) (*Verifier, error) {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	v := &Verifier{clock: clock, by: map[[credentials.TokenDigestLength]byte]entry{}}
	if doc == nil || lookup == nil {
		return v, nil
	}
	for _, tok := range doc.API.BootstrapTokens {
		if !tok.Token.Set() {
			continue
		}
		raw, err := lookup(tok.Token)
		if err != nil {
			return nil, err
		}
		mat := credentials.NewTokenMaterial(raw)
		wipe(raw)
		idx := credentials.DigestIndex(credentials.DigestToken(mat))
		mat.Wipe()
		v.by[idx] = entry{id: tok.ID, scopes: append([]string(nil), tok.Scopes...), expiresAt: tok.ExpiresAt}
	}
	return v, nil
}

// Authenticate verifies a raw bearer token (no "Bearer " prefix).
func (v *Verifier) Authenticate(token string) (Principal, error) {
	if v == nil {
		return Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	if token == "" {
		return Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	mat := credentials.NewTokenMaterial([]byte(token))
	idx := credentials.DigestIndex(credentials.DigestToken(mat))
	mat.Wipe()
	v.mu.RLock()
	got, ok := v.by[idx]
	v.mu.RUnlock()
	if !ok {
		return Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	if got.expiresAt != nil && !v.clock.Now().Before(got.expiresAt.UTC()) {
		return Principal{}, domain.NewError(domain.CodeUnauthenticated, "authentication required")
	}
	return Principal{ID: got.id, Scopes: append([]string(nil), got.scopes...)}, nil
}

// ParseBearer extracts the token from an Authorization header value.
func ParseBearer(header string) (string, bool) {
	const p = "bearer "
	if len(header) < len(p) {
		return "", false
	}
	if !strings.EqualFold(header[:len(p)], p) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(p):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

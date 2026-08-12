package aaa

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// snapshotStore reads credential material from the published snapshot.
type snapshotStore struct {
	snapshot func() *state.Snapshot
	secrets  config.SecretLookup
	clientID string
}

func (s snapshotStore) Lookup(userID string) (credentials.Record, bool) {
	if s.snapshot == nil {
		return credentials.Record{}, false
	}
	snap := s.snapshot()
	if snap == nil {
		return credentials.Record{}, false
	}
	u, ok := snap.User(userID)
	if !ok {
		return credentials.Record{}, false
	}
	rec := credentials.Record{
		ID:          u.User.ID,
		Enabled:     u.User.Enabled,
		Restricted:  clientRestricted(u.User.Restrictions.ClientIDs, s.clientID),
		ValidAfter:  u.User.Restrictions.ValidAfter,
		ValidBefore: u.User.Restrictions.ValidBefore,
	}
	if ref := u.User.Credentials.Login.Verifier; ref.Set() {
		if b, ok := resolveSecret(snap, s.secrets, ref); ok {
			rec.Login = credentials.NewLoginVerifier(b)
			wipe(b)
		}
	}
	if ref := u.User.Credentials.Challenge.Secret; ref.Set() {
		if b, ok := resolveSecret(snap, s.secrets, ref); ok {
			rec.Challenge = credentials.NewChallengeSecret(b)
			wipe(b)
		}
	}
	if ref := u.User.Credentials.Enable.Verifier; ref.Set() {
		if b, ok := resolveSecret(snap, s.secrets, ref); ok {
			rec.Enable = credentials.NewEnableVerifier(b)
			wipe(b)
		}
	}
	return rec, true
}

func resolveSecret(snap *state.Snapshot, lookup config.SecretLookup, ref config.SecretRef) ([]byte, bool) {
	if ref.MemoryID != "" && snap != nil {
		if b, ok := snap.RuntimeSecret(ref.MemoryID); ok {
			return b, true
		}
	}
	if lookup == nil || !ref.Set() || ref.MemoryID != "" {
		return nil, false
	}
	b, err := lookup(ref)
	if err != nil {
		return nil, false
	}
	return b, true
}

func clientRestricted(allowed []string, clientID string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, id := range allowed {
		if id == clientID {
			return false
		}
	}
	return true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

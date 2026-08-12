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
		ValidAfter:  u.User.Restrictions.ValidAfter,
		ValidBefore: u.User.Restrictions.ValidBefore,
	}
	if s.secrets != nil {
		if ref := u.User.Credentials.Login.Verifier; ref.Set() {
			if b, err := s.secrets(ref); err == nil {
				rec.Login = credentials.NewLoginVerifier(b)
				wipe(b)
			}
		}
		if ref := u.User.Credentials.Challenge.Secret; ref.Set() {
			if b, err := s.secrets(ref); err == nil {
				rec.Challenge = credentials.NewChallengeSecret(b)
				wipe(b)
			}
		}
		if ref := u.User.Credentials.Enable.Verifier; ref.Set() {
			if b, err := s.secrets(ref); err == nil {
				rec.Enable = credentials.NewEnableVerifier(b)
				wipe(b)
			}
		}
	}
	return rec, true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

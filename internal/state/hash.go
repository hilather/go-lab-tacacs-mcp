package state

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Baseline configuration contains references, never resolved secret bytes.
// Normalize the source schema and identity collections so equivalent v1/v2
// documents and map insertion order produce the same configuration identity.
func hashBaseline(doc *config.Document) (string, error) {
	canonical := cloneDocument(doc)
	canonical.SchemaVersion = config.SchemaVersionV2
	sort.Slice(canonical.Users, func(i, j int) bool { return canonical.Users[i].ID < canonical.Users[j].ID })
	sort.Slice(canonical.Groups, func(i, j int) bool { return canonical.Groups[i].ID < canonical.Groups[j].ID })
	sort.Slice(canonical.Clients, func(i, j int) bool { return canonical.Clients[i].ID < canonical.Clients[j].ID })
	sort.Slice(canonical.API.BootstrapTokens, func(i, j int) bool { return canonical.API.BootstrapTokens[i].ID < canonical.API.BootstrapTokens[j].ID })
	sort.Slice(canonical.RADIUSPolicies, func(i, j int) bool { return canonical.RADIUSPolicies[i].ID < canonical.RADIUSPolicies[j].ID })
	sort.Slice(canonical.RADIUSReplyProfiles, func(i, j int) bool { return canonical.RADIUSReplyProfiles[i].ID < canonical.RADIUSReplyProfiles[j].ID })
	sort.Slice(canonical.RADIUSDictionaries, func(i, j int) bool { return canonical.RADIUSDictionaries[i].ID < canonical.RADIUSDictionaries[j].ID })
	return hashJSON(canonical)
}

type hashEntry struct {
	Deleted bool
	Source  domain.ObjectSource
	Value   any
}

type hashToken struct {
	ID              string
	Name            string
	Scopes          []string
	Enabled         bool
	ExpiresAt       *time.Time
	MaterialVersion string
}

func hashOverlay(ov overlay, key []byte) (string, error) {
	view := struct {
		Users    map[string]hashEntry
		Groups   map[string]hashEntry
		Clients  map[string]hashEntry
		Tokens   map[string]hashEntry
		Secrets  map[string]string
		Fallback *config.RuleSet
	}{Users: map[string]hashEntry{}, Groups: map[string]hashEntry{}, Clients: map[string]hashEntry{}, Tokens: map[string]hashEntry{}, Secrets: map[string]string{}, Fallback: ov.fallback}
	for id, e := range ov.users {
		entry := hashEntry{Deleted: e.deleted, Source: e.meta.Source}
		if !e.deleted {
			entry.Value = e.user
		}
		view.Users[id] = entry
	}
	for id, e := range ov.groups {
		entry := hashEntry{Deleted: e.deleted, Source: e.meta.Source}
		if !e.deleted {
			entry.Value = e.group
		}
		view.Groups[id] = entry
	}
	for id, e := range ov.clients {
		entry := hashEntry{Deleted: e.deleted, Source: e.meta.Source}
		if !e.deleted {
			entry.Value = e.client
		}
		view.Clients[id] = entry
	}
	for id, e := range ov.tokens {
		entry := hashEntry{Deleted: e.deleted, Source: e.meta.Source}
		if !e.deleted {
			raw := e.token.Digest.Bytes()
			entry.Value = hashToken{ID: e.token.ID, Name: e.token.Name, Scopes: e.token.Scopes, Enabled: e.token.Enabled, ExpiresAt: e.token.ExpiresAt, MaterialVersion: secretVersion(raw, key)}
			wipeBytes(raw)
		}
		view.Tokens[id] = entry
	}
	for id, raw := range ov.secrets {
		view.Secrets[id] = secretVersion(raw, key)
	}
	return hashJSON(view)
}

// Secret versions are process-keyed and only contribute to the final aggregate
// hash. Neither raw material nor individual fingerprints leave this function.
func secretVersion(raw, key []byte) string {
	if len(raw) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("taclab-state-hash-v2\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func hashJSON(value any) (string, error) {
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(value); err != nil {
		return "", domain.NewError(domain.CodeInternal, "cannot fingerprint state")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

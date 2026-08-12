package auth

import (
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

// SecretLookup builds a file/env lookup from the document security flags.
func SecretLookup(doc *config.Document, extra config.ReadOptions) config.SecretLookup {
	opts := extra
	if doc != nil {
		opts.AllowEnvironment = doc.Security.AllowEnvironmentSecrets
		if !opts.StrictFilesSet {
			opts.StrictFiles = doc.Security.StrictSecretFiles
			opts.StrictFilesSet = true
		}
	}
	return config.FileLookup(opts)
}

// LoadBootstrap verifies every live bootstrap token against the published
// snapshot. Missing files fail closed. Runtime overlay tokens are ignored.
func LoadBootstrap(snap *state.Snapshot, lookup config.SecretLookup) error {
	if snap == nil {
		return domain.NewError(domain.CodeUnavailable, "no published snapshot")
	}
	if lookup == nil {
		return domain.NewError(domain.CodeInvalidArgument, "secret lookup is required")
	}
	settings := snap.Settings()
	if settings == nil {
		return nil
	}
	now := snap.CompiledAt
	for _, boot := range settings.API.BootstrapTokens {
		tok, ok := snap.Token(boot.ID)
		if !ok {
			continue
		}
		if tok.Meta.Source != domain.SourceConfig {
			continue
		}
		if !boot.Token.Set() {
			return domain.NewError(domain.CodeAuthMethodCredentialMissing, "bootstrap token secret is required").WithPath("api.bootstrap_tokens/" + boot.ID)
		}
		raw, err := lookup(boot.Token)
		if err != nil {
			return err
		}
		got, aerr := snap.AuthenticateToken(raw, now)
		wipeBytes(raw)
		if aerr != nil || got.ID != boot.ID {
			return domain.NewError(domain.CodeUnauthenticated, "bootstrap token did not authenticate").WithPath("api.bootstrap_tokens/" + tok.ID)
		}
	}
	return nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

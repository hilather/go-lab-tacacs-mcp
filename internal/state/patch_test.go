package state

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestPatchDisplayNamePreservesVerifiers(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	snap, err := m.UpdateUser("alice", UpdateUser{DisplayName: strPtr("Alice Prime")}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("alice")
	if !ok {
		t.Fatal("missing alice")
	}
	if u.User.DisplayName != "Alice Prime" {
		t.Fatalf("display=%q", u.User.DisplayName)
	}
	if u.User.Credentials.Login.Verifier.File != "/run/secrets/alice-login" {
		t.Fatalf("login verifier dropped: %+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File != "/run/secrets/alice-chal" {
		t.Fatalf("challenge dropped: %+v", u.User.Credentials.Challenge.Secret)
	}
	if u.User.Credentials.Enable.Verifier.File != "/run/secrets/alice-enable" {
		t.Fatalf("enable dropped: %+v", u.User.Credentials.Enable.Verifier)
	}
	if u.Meta.Source != domain.SourceOverride || u.Meta.ShadowsSource != domain.SourceConfig {
		t.Fatalf("meta=%+v", u.Meta)
	}
}

func TestCreateOverrideInheritsOmittedSecrets(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	snap, err := m.CreateUser(CreateUser{
		ID:          "alice",
		DisplayName: strPtr("Alice Override"),
		Override:    true,
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := snap.User("alice")
	if !ok {
		t.Fatal("missing")
	}
	if u.User.DisplayName != "Alice Override" {
		t.Fatalf("display=%q", u.User.DisplayName)
	}
	if u.User.Credentials.Login.Verifier.File != "/run/secrets/alice-login" {
		t.Fatalf("login not inherited: %+v", u.User.Credentials.Login.Verifier)
	}
	if u.User.Credentials.Challenge.Secret.File != "/run/secrets/alice-chal" {
		t.Fatal("challenge not inherited")
	}
	if u.User.GroupIDs[0] != "ops" {
		t.Fatalf("groups=%v", u.User.GroupIDs)
	}
	if u.Meta.Source != domain.SourceOverride {
		t.Fatalf("source=%s", u.Meta.Source)
	}
}

func TestCreateWithoutOverrideAlreadyExists(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	_, err := m.CreateUser(CreateUser{ID: "alice", DisplayName: strPtr("x")}, nil)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeAlreadyExists {
		t.Fatalf("got %v", err)
	}
	if m.Revision() != 1 {
		t.Fatalf("revision moved: %d", m.Revision())
	}
}

func TestNullSecretWhileMethodEnabledRejected(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	_, err := m.UpdateUser("alice", UpdateUser{Login: &SecretPatch{Clear: true}}, &rev)
	de, ok := domain.AsError(err)
	if !ok || de.Code != domain.CodeAuthMethodCredentialMissing {
		t.Fatalf("got %v", err)
	}
	u, _ := m.Snapshot().User("alice")
	if u.User.Credentials.Login.Verifier.File == "" {
		t.Fatal("verifier must remain")
	}
	if m.Revision() != 1 {
		t.Fatalf("published invalid candidate: %d", m.Revision())
	}

	_, err = m.UpdateClient("sw", UpdateClient{SharedSecret: &SecretPatch{Clear: true}}, &rev)
	de, ok = domain.AsError(err)
	if !ok || de.Code != domain.CodeAuthMethodCredentialMissing {
		t.Fatalf("client clear: %v", err)
	}
}

func TestUserOptionalSecretNullAndDisabledLogin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		patch   UpdateUser
		wantErr domain.Code
		check   func(t *testing.T, u EffectiveUser)
	}{
		{
			name:  "null challenge while enabled",
			patch: UpdateUser{Challenge: &SecretPatch{Clear: true}},
			check: func(t *testing.T, u EffectiveUser) {
				t.Helper()
				if u.User.Credentials.Challenge.Secret.Set() {
					t.Fatal("challenge should be cleared")
				}
				if !u.User.Credentials.Login.Verifier.Set() {
					t.Fatal("login must remain")
				}
			},
		},
		{
			name:  "null enable while enabled",
			patch: UpdateUser{Enable: &SecretPatch{Clear: true}},
			check: func(t *testing.T, u EffectiveUser) {
				t.Helper()
				if u.User.Credentials.Enable.Verifier.Set() {
					t.Fatal("enable should be cleared")
				}
			},
		},
		{
			name:    "null login while enabled",
			patch:   UpdateUser{Login: &SecretPatch{Clear: true}},
			wantErr: domain.CodeAuthMethodCredentialMissing,
		},
		{
			name:  "null login while disabled in same patch",
			patch: UpdateUser{Enabled: boolPtr(false), Login: &SecretPatch{Clear: true}},
			check: func(t *testing.T, u EffectiveUser) {
				t.Helper()
				if u.User.Enabled {
					t.Fatal("user should be disabled")
				}
				if u.User.Credentials.Login.Verifier.Set() {
					t.Fatal("login should be cleared")
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := mustMgr(t, smallYAML)
			rev := m.Revision()
			snap, err := m.UpdateUser("alice", tc.patch, &rev)
			if tc.wantErr != "" {
				de, ok := domain.AsError(err)
				if !ok || de.Code != tc.wantErr {
					t.Fatalf("got %v", err)
				}
				if m.Revision() != 1 {
					t.Fatalf("published invalid candidate: %d", m.Revision())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			u, ok := snap.User("alice")
			if !ok {
				t.Fatal("missing alice")
			}
			tc.check(t, u)
		})
	}

	t.Run("null login on already disabled user", func(t *testing.T) {
		t.Parallel()
		m := mustMgr(t, smallYAML)
		rev := m.Revision()
		if _, err := m.UpdateUser("alice", UpdateUser{Enabled: boolPtr(false)}, &rev); err != nil {
			t.Fatal(err)
		}
		rev = m.Revision()
		snap, err := m.UpdateUser("alice", UpdateUser{Login: &SecretPatch{Clear: true}}, &rev)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := snap.User("alice")
		if u.User.Enabled || u.User.Credentials.Login.Verifier.Set() {
			t.Fatalf("disabled user login should clear: enabled=%v login=%v", u.User.Enabled, u.User.Credentials.Login.Verifier)
		}
	})
}

func TestNullClientSecretWhenLegacyDisabled(t *testing.T) {
	t.Parallel()
	m := mustMgr(t, smallYAML)
	rev := m.Revision()
	match := config.ClientMatch{
		SourceCIDRs: []string{"10.20.0.0/16"},
		Transports:  []domain.Transport{domain.TransportTLS},
		Mode:        domain.MatchAddressAndCertificate,
	}
	_, err := m.UpdateClient("sw", UpdateClient{
		Match:        &match,
		SharedSecret: &SecretPatch{Clear: true},
	}, &rev)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := m.Snapshot().Client("sw")
	if c.Client.Legacy.SharedSecret.Set() {
		t.Fatal("secret should be cleared when legacy is disabled")
	}
}

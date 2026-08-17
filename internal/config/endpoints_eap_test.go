package config

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestRADIUSAuthMethodsEAPOptIn(t *testing.T) {
	t.Parallel()
	got, err := ParseRADIUSAuthMethods([]string{"pap", "chap", "eap"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != RADIUSAuthMethodEAP {
		t.Fatalf("%v", got)
	}
	got, err = ParseRADIUSAuthMethods([]string{"EAP", "pap"})
	if err != nil || len(got) != 2 || got[0] != RADIUSAuthMethodEAP {
		t.Fatalf("%v %v", got, err)
	}
	got, err = ParseRADIUSAuthMethods([]string{"mschapv1"})
	if err != nil || len(got) != 1 || got[0] != RADIUSAuthMethodMSCHAPv1 {
		t.Fatalf("mschapv1 opt-in=%v err=%v", got, err)
	}
	got, err = ParseRADIUSAuthMethods([]string{"peap"})
	if err != nil || len(got) != 1 || got[0] != RADIUSAuthMethodPEAP {
		t.Fatalf("peap opt-in=%v err=%v", got, err)
	}
	if _, err := ParseRADIUSAuthMethods([]string{"ttls"}); err == nil {
		t.Fatal("unknown token")
	}

	empty, err := normalizeRADIUSAuthMethods(nil, "radius.allowed_authentication_methods")
	if err != nil || empty != nil {
		t.Fatalf("omitted=%v err=%v", empty, err)
	}
	zero, err := normalizeRADIUSAuthMethods([]string{}, "radius.allowed_authentication_methods")
	if err != nil || len(zero) != 0 {
		t.Fatalf("empty list=%v err=%v", zero, err)
	}

	ep, err := normalizeRADIUSEndpoint(&rawRADIUSEndpoint{
		SharedSecret: &rawSecretRef{Environment: "TACLAB_TEST_RADIUS_SECRET"},
	}, "clients[0].endpoints[0].radius", true, RADIUSListener{}, []domain.ListenerRole{domain.RoleAccess})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ep.AllowedAuthenticationMethods, ",") != "pap,chap" {
		t.Fatalf("default=%v", ep.AllowedAuthenticationMethods)
	}
	for _, m := range ep.AllowedAuthenticationMethods {
		if m == RADIUSAuthMethodEAP || m == RADIUSAuthMethodPEAP {
			t.Fatal("eap/peap must be opt-in")
		}
	}
	if len(ep.AllowedAuthenticationMethods) == 0 {
		t.Fatal("compiled access methods must not be empty")
	}

	filled := FillRADIUSAccessMethods(nil, []domain.ListenerRole{domain.RoleAccess})
	if strings.Join(filled, ",") != "pap,chap" {
		t.Fatalf("fill omitted=%v", filled)
	}
	filled = FillRADIUSAccessMethods([]string{}, []domain.ListenerRole{domain.RoleAccess})
	if strings.Join(filled, ",") != "pap,chap" {
		t.Fatalf("fill empty=%v", filled)
	}
	kept := FillRADIUSAccessMethods([]string{RADIUSAuthMethodEAP}, []domain.ListenerRole{domain.RoleAccess})
	if strings.Join(kept, ",") != "eap" {
		t.Fatalf("explicit eap overwritten: %v", kept)
	}
	acct := FillRADIUSAccessMethods(nil, []domain.ListenerRole{domain.RoleAccounting})
	if len(acct) != 0 {
		t.Fatalf("accounting-only must not invent methods: %v", acct)
	}
}

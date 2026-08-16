package domain

import (
	"strings"
	"testing"
)

func TestAuthMethodRoundTripAndPAPAlias(t *testing.T) {
	t.Parallel()
	if AuthMethodPassword.String() != "password" {
		t.Fatalf("AuthMethodPassword=%q", AuthMethodPassword)
	}
	if !AuthMethodPassword.Valid() || !AuthMethodCHAP.Valid() || !AuthMethodMSCHAPv1.Valid() || !AuthMethodMSCHAPv2.Valid() || !AuthMethodEAP.Valid() {
		t.Fatal("canonical methods must be valid")
	}
	got, err := ParseAuthMethod("password")
	if err != nil || got != AuthMethodPassword {
		t.Fatalf("password: %v %v", got, err)
	}
	got, err = ParseAuthMethod("pap")
	if err != nil || got != AuthMethodPassword {
		t.Fatalf("pap alias: %v %v", got, err)
	}
	if got.String() != "password" {
		t.Fatalf("pap must store password, got %q", got)
	}
	got, err = ParseAuthMethod("PAP")
	if err != nil || got != AuthMethodPassword || got.String() != "password" {
		t.Fatalf("PAP alias: %v %v", got, err)
	}
	got, err = ParseAuthMethod("chap")
	if err != nil || got != AuthMethodCHAP {
		t.Fatalf("chap: %v %v", got, err)
	}
	got, err = ParseAuthMethod("mschapv1")
	if err != nil || got != AuthMethodMSCHAPv1 {
		t.Fatalf("mschapv1: %v %v", got, err)
	}
	got, err = ParseAuthMethod("MSCHAPV2")
	if err != nil || got != AuthMethodMSCHAPv2 {
		t.Fatalf("mschapv2: %v %v", got, err)
	}
	got, err = ParseAuthMethod("eap")
	if err != nil || got != AuthMethodEAP || got.String() != "eap" {
		t.Fatalf("eap: %v %v", got, err)
	}
	got, err = ParseAuthMethod("EAP")
	if err != nil || got != AuthMethodEAP {
		t.Fatalf("EAP: %v %v", got, err)
	}
	if AuthMethod("pap").Valid() {
		t.Fatal("pap is a parse alias, not a stored value")
	}
	if AuthMethod("").Valid() {
		t.Fatal("empty method")
	}
}

func TestParseAuthMethodRejectsPasswdAndUnknown(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"passwd", "mschap", "ascii", "enable", "eap", ""} {
		got, err := ParseAuthMethod(s)
		if err == nil || got != "" {
			t.Fatalf("ParseAuthMethod(%q)=%q err=%v", s, got, err)
		}
		de, ok := AsError(err)
		if !ok || de.Code != CodeInvalidArgument {
			t.Fatalf("ParseAuthMethod(%q) code=%v err=%v", s, de, err)
		}
		if s == "passwd" {
			msg := strings.ToLower(de.Message)
			for _, token := range []string{"password", "pap", "chap", "mschapv1", "mschapv2", "eap"} {
				if !strings.Contains(msg, token) {
					t.Fatalf("passwd error must name %q: %q", token, de.Message)
				}
			}
		}
	}
}

func TestEffectRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []Effect{EffectPermit, EffectDeny, EffectError}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseEffect(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if _, err := ParseEffect("permit_add"); err == nil {
		t.Fatal("TACACS AuthorDecision must not parse as Effect")
	}
	if _, err := ParseEffect(""); err == nil {
		t.Fatal("empty effect")
	}
}

func TestAuthOutcomeRoundTrip(t *testing.T) {
	t.Parallel()
	vals := []AuthOutcome{AuthPass, AuthReject, AuthChallenge, AuthError}
	for _, v := range vals {
		if !v.Valid() || v.String() == "" {
			t.Fatalf("%v", v)
		}
		got, err := ParseAuthOutcome(v.String())
		if err != nil || got != v {
			t.Fatalf("Parse(%q)=%v err=%v", v.String(), got, err)
		}
	}
	if AuthPass.String() != "pass" || AuthReject.String() != "reject" {
		t.Fatalf("%q %q", AuthPass, AuthReject)
	}
	if _, err := ParseAuthOutcome("fail"); err == nil {
		t.Fatal("TACACS AuthenStatus fail is not AuthOutcome")
	}
	if _, err := ParseAuthOutcome(""); err == nil {
		t.Fatal("empty outcome")
	}
}

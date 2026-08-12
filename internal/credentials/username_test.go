package credentials

import (
	"testing"
)

func TestCanonicalUsernamePreservesCase(t *testing.T) {
	t.Parallel()
	got, err := CanonicalUsername("LabAdmin")
	if err != nil {
		t.Fatal(err)
	}
	if got != "LabAdmin" {
		t.Fatalf("got %q, want case preserved", got)
	}
	folded, err := CanonicalUsername("labadmin")
	if err != nil {
		t.Fatal(err)
	}
	if folded == got {
		t.Fatal("UsernameCasePreserved must not fold ASCII case")
	}
}

func TestCanonicalUsernameRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := CanonicalUsername(""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := CanonicalUsername("\x00"); err == nil {
		t.Fatal("expected error for NUL")
	}
}

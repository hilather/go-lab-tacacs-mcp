package state

import "testing"

func TestValidateCandidateUsesReloadResetOverlay(t *testing.T) {
	m := mustMgr(t, smallYAML)
	if _, err := m.CreateUser(CreateUser{ID: "runtime-user"}, nil); err != nil {
		t.Fatal(err)
	}
	candidate := mustParse(t, smallYAML)
	candidate.Runtime.ReloadOverlayBehavior = "reset"
	candidate.Runtime.MaxObjects.Users = 1
	before := m.Snapshot()
	if err := m.ValidateCandidate(candidate); err != nil {
		t.Fatalf("candidate reload would discard runtime user but validation rejected it: %v", err)
	}
	if m.Snapshot() != before {
		t.Fatal("validation published state")
	}
	after, err := m.Reload(candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.User("runtime-user"); ok {
		t.Fatal("reset reload retained overlay")
	}
}

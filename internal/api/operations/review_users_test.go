package operations

import (
	"context"
	"testing"
)

func TestUsersOperationsNormalizeIdentifiers(t *testing.T) {
	m := mustMgr(t, smallYAML)
	reg := mustStateRegistry(t, m)
	actor := Actor{ID: "op", Scopes: []string{"state:read", "state:write"}}
	id := "Ａlice"
	canonical := "Alice"
	created, err := reg.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), Input{Actor: actor, Request: CreateUserRequest{ID: id}})
	if err != nil {
		t.Fatalf("create mutated revision to %d but returned %v", m.Revision(), err)
	}
	if created.Data.(User).ID != canonical {
		t.Fatalf("created ID=%q", created.Data.(User).ID)
	}
	got, err := reg.Invoke(context.Background(), IDUsersGet, m.Snapshot(), Input{Actor: actor, Request: GetUserRequest{ID: id}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Data.(User).ID != canonical {
		t.Fatalf("get ID=%q", got.Data.(User).ID)
	}
	name := "normalized"
	updated, err := reg.Invoke(context.Background(), IDUsersUpdate, m.Snapshot(), Input{Actor: actor, Request: UpdateUserRequest{ID: id, DisplayName: &name}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Data.(User).ID != canonical || updated.Data.(User).DisplayName != name {
		t.Fatalf("update=%+v", updated.Data)
	}
	deleted, err := reg.Invoke(context.Background(), IDUsersDelete, m.Snapshot(), Input{Actor: actor, Request: DeleteUserRequest{ID: id}})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Data.(DeleteResult).ID != canonical {
		t.Fatalf("delete=%+v", deleted.Data)
	}
}

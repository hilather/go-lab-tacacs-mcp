package operations

import (
	"context"
	"errors"
	"fmt"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIdempotencyReplaysOriginalRevision(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	rev := m.Revision()
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, ExpectedRevision: &rev, IdempotencyKey: "create-1", Request: CreateUserRequest{ID: "replayed"}}
	first, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in)
	if err != nil {
		t.Fatalf("retry original revision: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replay differs: %#v %#v", first, second)
	}
	if m.Revision() != first.Revision {
		t.Fatal("retry mutated state")
	}
}

func TestIdempotencyMismatchAuthorizationAndUnsupported(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a"}}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
		t.Fatal(err)
	}
	in.Request = CreateUserRequest{ID: "b"}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeConflict, "")) {
		t.Fatalf("mismatch: %v", err)
	}
	in.Actor.Scopes = nil
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodePermissionDenied, "")) {
		t.Fatalf("authorization: %v", err)
	}
	in.Actor.Scopes = []string{"tokens:manage"}
	in.Request = CreateTokenRequest{}
	rev := m.Revision()
	if _, err := r.Invoke(context.Background(), IDTokensCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeInvalidArgument, "")) {
		t.Fatalf("one-time token: %v", err)
	}
	if m.Revision() != rev {
		t.Fatal("unsupported key mutated state")
	}
}

func TestIdempotencyConcurrentAndExpiry(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	now := time.Unix(0, 0)
	r.replay.now = func() time.Time { return now }
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a"}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
				t.Errorf("concurrent retry: %v", err)
			}
		}()
	}
	wg.Wait()
	now = now.Add(11 * time.Minute)
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeAlreadyExists, "")) {
		t.Fatalf("expired replay: %v", err)
	}
}

func TestIdempotencyCapacityAndKeyLimit(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	r.replay.capacity = 1
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a"}}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	in.IdempotencyKey = "second"
	in.Request = CreateUserRequest{ID: "b"}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeUnavailable, "")) {
		t.Fatalf("capacity: %v", err)
	}
	in.IdempotencyKey = strings.Repeat("x", 257)
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeInvalidArgument, "")) {
		t.Fatalf("key limit: %v", err)
	}
	if m.Revision() != rev {
		t.Fatal("admission failure mutated state")
	}
}

func TestIdempotencyWaitCancellationAndPendingAdmission(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	r.replay.capacity = 1
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	got := r.ops[IDUsersCreate]
	original := got.handle
	got.handle = func(ctx context.Context, snap *state.Snapshot, in Input) (any, error) {
		close(entered)
		<-release
		return original(ctx, snap, in)
	}
	r.ops[IDUsersCreate] = got
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a"}}
	go func() { _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); finished <- err }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Invoke(ctx, IDUsersCreate, m.Snapshot(), in); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait cancellation: %v", err)
	}
	other := in
	other.IdempotencyKey = "other"
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), other); !errors.Is(err, domain.NewError(domain.CodeUnavailable, "")) {
		t.Fatalf("pending admission: %v", err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
		t.Fatal(err)
	}
}

func TestIdempotencyResponseIsolationAndOversizeTombstone(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		t.Run(fmt.Sprint(oversize), func(t *testing.T) {
			m := mustMgr(t, smallYAML)
			r := mustStateRegistry(t, m)
			value := "original"
			if oversize {
				value = strings.Repeat("x", replayReservation+1)
			}
			labels := map[string]string{"label": value}
			in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a", Labels: &labels}}
			first, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in)
			if err != nil {
				t.Fatal(err)
			}
			first.Data.(User).Labels["label"] = "caller mutation"
			second, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in)
			if oversize {
				if !errors.Is(err, domain.NewError(domain.CodeUnavailable, "")) {
					t.Fatalf("oversize replay: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if second.Data.(User).Labels["label"] != "original" {
					t.Fatal("caller changed replay")
				}
			}
			if m.Revision() != first.Revision {
				t.Fatal("replay repeated effects")
			}
		})
	}
}

func TestIdempotencySemanticFingerprint(t *testing.T) {
	s := newReplayStore()
	a := CreateUserRequest{ID: "a"}
	b := a
	b.Login = OptionalSecret{Present: true, Clear: true}
	one, _ := s.digest(requestSemantics(a))
	two, _ := s.digest(requestSemantics(b))
	if one == two {
		t.Fatal("omission aliases explicit secret clear")
	}
}

func TestIdempotencyPanicCompletesReservation(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	got := r.ops[IDUsersCreate]
	got.handle = func(context.Context, *state.Snapshot, Input) (any, error) { panic("handler failure") }
	r.ops[IDUsersCreate] = got
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "panic", Request: CreateUserRequest{ID: "a"}}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("handler panic suppressed")
			}
		}()
		r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.Invoke(ctx, IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeUnavailable, "")) {
		t.Fatalf("panic replay: %v", err)
	}
}

func TestIdempotencyTokenIncarnationIsolation(t *testing.T) {
	m := mustMgr(t, smallYAML)
	r := mustStateRegistry(t, m)
	createToken := func(material string) {
		rev := m.Revision()
		if _, err := m.CreateToken(state.CreateToken{ID: "writer", Name: "writer", Scopes: []string{"state:write"}, Material: credentials.NewTokenMaterial([]byte(material))}, &rev); err != nil {
			t.Fatal(err)
		}
	}
	createToken(strings.Repeat("a", 32))
	in := Input{Actor: Actor{ID: "writer", Scopes: []string{"state:write"}}, IdempotencyKey: "key", Request: CreateUserRequest{ID: "a"}}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
		t.Fatal(err)
	}
	rev := m.Revision()
	if _, err := m.DeleteToken("writer", state.DeleteOptions{}, &rev); err != nil {
		t.Fatal(err)
	}
	createToken(strings.Repeat("b", 32))
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); !errors.Is(err, domain.NewError(domain.CodeAlreadyExists, "")) {
		t.Fatalf("new token incarnation reused old replay: %v", err)
	}
}

package operations

import (
	"context"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"testing"
)

func BenchmarkRegistryInvokeRead(b *testing.B) {
	doc, err := config.Parse([]byte(smallYAML))
	if err != nil {
		b.Fatal(err)
	}
	m, err := state.New(doc, state.Options{})
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewFromRepo(".", Deps{State: m})
	if err != nil {
		b.Fatal(err)
	}
	snap := m.Snapshot()
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:read"}}, Request: GetUserRequest{ID: "alice"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Invoke(context.Background(), IDUsersGet, snap, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRegistryInvokeReplay(b *testing.B) {
	doc, err := config.Parse([]byte(smallYAML))
	if err != nil {
		b.Fatal(err)
	}
	m, err := state.New(doc, state.Options{})
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewFromRepo(".", Deps{State: m})
	if err != nil {
		b.Fatal(err)
	}
	in := Input{Actor: Actor{ID: "op", Scopes: []string{"state:write"}}, IdempotencyKey: "bench", Request: CreateUserRequest{ID: "bench"}}
	if _, err := r.Invoke(context.Background(), IDUsersCreate, m.Snapshot(), in); err != nil {
		b.Fatal(err)
	}
	snap := m.Snapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Invoke(context.Background(), IDUsersCreate, snap, in); err != nil {
			b.Fatal(err)
		}
	}
}

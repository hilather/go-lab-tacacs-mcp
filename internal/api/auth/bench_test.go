package auth

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func BenchmarkVerifyBearer(b *testing.B) {
	m, value, clock := mustTokenMgr(b, []string{"state:read"}, nil)
	svc := New(Options{Clock: clock})
	snap := m.Snapshot()
	raw := []byte(value)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.VerifyBearer(raw, snap); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticateToken(b *testing.B) {
	m, value, _ := mustTokenMgr(b, []string{"state:read"}, nil)
	snap := m.Snapshot()
	raw := []byte(value)
	now := snap.CompiledAt
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := snap.AuthenticateToken(raw, now); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = credentials.TokenByteLength
var _ = state.CreateToken{}

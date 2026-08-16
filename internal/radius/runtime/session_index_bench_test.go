package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func BenchmarkSessionIndexLookup(b *testing.B) {
	idx, err := NewSessionIndex(Options{
		MaxEntries: 20000,
		MaxBytes:   8 << 20,
		TTL:        24 * time.Hour,
		Clock:      domain.SystemClock{},
		Entropy:    strings.NewReader(strings.Repeat("0123456789abcdef", 4096)),
	})
	if err != nil {
		b.Fatal(err)
	}
	if !idx.Apply(startEv("bench-session")) {
		b.Fatal("insert")
	}
	key := SessionKey{EndpointID: "acct-udp", AcctSessionID: "bench-session"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := idx.LookupKey(key); !ok {
			b.Fatal("missing")
		}
	}
}

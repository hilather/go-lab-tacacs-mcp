package runtime

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestSessionIndexRace(t *testing.T) {
	idx, err := NewSessionIndex(Options{
		MaxEntries: 256,
		MaxBytes:   1 << 20,
		TTL:        time.Hour,
		Clock:      domain.SystemClock{},
		Entropy:    rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				ev := startEv(string(rune('a'+n)) + string(rune('0'+j%10)))
				_ = idx.Apply(ev)
				_ = idx.List("", 10)
				_ = idx.Len()
				if j%7 == 0 {
					ev.Kind = EventStop
					_ = idx.Apply(ev)
				}
				if j%11 == 0 {
					ev.Kind = EventOn
					_ = idx.Apply(ev)
				}
			}
		}(i)
	}
	wg.Wait()
}

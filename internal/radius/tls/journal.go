package tls

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
)

type journal struct {
	mu         sync.Mutex
	entries    map[server.JournalKey]time.Time
	sizes      map[server.JournalKey]int
	maxEntries int
	maxBytes   int
	usedBytes  int
	ttl        time.Duration
	now        func() time.Time
	sat        atomic.Uint64
}

func newJournal(entries, bytes int, ttl time.Duration, now func() time.Time) *journal {
	if entries <= 0 {
		entries = 20000
	}
	if bytes <= 0 {
		bytes = 8 << 20
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &journal{
		entries:    make(map[server.JournalKey]time.Time, entries),
		sizes:      make(map[server.JournalKey]int, entries),
		maxEntries: entries,
		maxBytes:   bytes,
		ttl:        ttl,
		now:        now,
	}
}

func journalKeyBytes(k server.JournalKey) int {
	return len(k.EndpointID) + len(k.SrcIP) + 2 + len(k.SessionID) + len(k.StatusType) + len(k.NAS) + len(k.Fingerprint)
}

func (j *journal) Seen(key server.JournalKey) bool {
	if j == nil {
		return false
	}
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.expireLocked(now)
	exp, ok := j.entries[key]
	return ok && exp.After(now)
}

func (j *journal) Remember(key server.JournalKey) bool {
	if j == nil {
		return false
	}
	now := j.now()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.expireLocked(now)
	if exp, ok := j.entries[key]; ok && exp.After(now) {
		j.entries[key] = now.Add(j.ttl)
		return true
	}
	n := journalKeyBytes(key)
	if len(j.entries) >= j.maxEntries || j.usedBytes+n > j.maxBytes {
		j.sat.Add(1)
		return false
	}
	j.entries[key] = now.Add(j.ttl)
	j.sizes[key] = n
	j.usedBytes += n
	return true
}

func (j *journal) expireLocked(now time.Time) {
	for k, exp := range j.entries {
		if !exp.After(now) {
			j.usedBytes -= j.sizes[k]
			if j.usedBytes < 0 {
				j.usedBytes = 0
			}
			delete(j.entries, k)
			delete(j.sizes, k)
		}
	}
}

type minuteSampler struct {
	mu    sync.Mutex
	limit int
	now   func() time.Time
	win   time.Time
	count int
}

func newMinuteSampler(limit int, now func() time.Time) *minuteSampler {
	if now == nil {
		now = time.Now
	}
	return &minuteSampler{limit: limit, now: now}
}

func (s *minuteSampler) Allow() bool {
	if s == nil || s.limit <= 0 {
		return false
	}
	now := s.now().UTC().Truncate(time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	if now != s.win {
		s.win = now
		s.count = 0
	}
	if s.count >= s.limit {
		return false
	}
	s.count++
	return true
}

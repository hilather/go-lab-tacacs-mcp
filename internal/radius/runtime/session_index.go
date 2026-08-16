package runtime

import (
	"io"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

// Accounting kinds that mutate the index. Unknown kinds are ignored.
const (
	EventStart   = "start"
	EventStop    = "stop"
	EventInterim = "interim_update"
	EventOn      = "accounting_on"
	EventOff     = "accounting_off"
)

// SessionKey is the durable index identity. Access-Accept never creates one.
type SessionKey struct {
	EndpointID    string
	AcctSessionID string
}

// SessionRecord is one live accounting session. EndpointID is index identity
// only; DAC originate must not use it as the CoA secret key.
type SessionRecord struct {
	Key           SessionKey
	Handle        string
	ClientID      string
	EndpointID    string
	UserID        string
	NASIP         netip.Addr
	NASIdentifier string
	NASPort       uint32
	Peer          netip.AddrPort
	Class         []byte
	StartedAt     time.Time
	LastUpdate    time.Time
	Revision      domain.Revision
	LastCoA       LastCoA
}

// LastCoA is identification-safe inbound CoA attrs stored for lab inspection.
type LastCoA struct {
	SessionTimeout *uint32
	IdleTimeout    *uint32
	ReplyMessage   []string
}

// DASQuery identifies a session for inbound Disconnect/CoA.
type DASQuery struct {
	ClientID      string
	SessionID     string
	UserID        string
	NASIP         netip.Addr
	NASIdentifier string
}

// AcctEvent is the post-ring-accept hook from RecordRADIUSAccounting.
type AcctEvent struct {
	Kind          string
	EndpointID    string
	ClientID      string
	UserID        string
	SessionID     string
	NASIP         netip.Addr
	NASIdentifier string
	NASPort       uint32
	Peer          netip.AddrPort
	Class         []byte
	StartedAt     time.Time
	Revision      domain.Revision
}

// Options construct a bounded in-memory session index.
type Options struct {
	MaxEntries int
	MaxBytes   int
	TTL        time.Duration
	Clock      domain.Clock
	Entropy    io.Reader
	Metrics    *observability.Recorder
}

// SessionIndex is the process-local CoA session table. Memory only.
type SessionIndex struct {
	maxEntries int
	maxBytes   int
	ttl        time.Duration
	clock      domain.Clock
	entropy    io.Reader
	metrics    *observability.Recorder

	mu       sync.Mutex
	byKey    map[SessionKey]string
	byHandle map[string]*SessionRecord
	bytes    int
}

// NewSessionIndex builds an empty table. Caps are required.
func NewSessionIndex(opts Options) (*SessionIndex, error) {
	if opts.MaxEntries <= 0 || opts.MaxBytes <= 0 || opts.TTL <= 0 {
		return nil, domain.NewError(domain.CodeInvalidArgument, "session index requires entries, bytes, and ttl caps")
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	if opts.Entropy == nil {
		return nil, domain.NewError(domain.CodeInvalidArgument, "session index entropy is required")
	}
	return &SessionIndex{
		maxEntries: opts.MaxEntries,
		maxBytes:   opts.MaxBytes,
		ttl:        opts.TTL,
		clock:      opts.Clock,
		entropy:    opts.Entropy,
		metrics:    opts.Metrics,
		byKey:      map[SessionKey]string{},
		byHandle:   map[string]*SessionRecord{},
	}, nil
}

// Apply updates the index after the accounting ring accepted the record.
// Start without Acct-Session-Id is a no-op. Saturation refuses new inserts
// and returns false; accounting still succeeded at the ring.
func (idx *SessionIndex) Apply(ev AcctEvent) bool {
	if idx == nil {
		return true
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	switch ev.Kind {
	case EventStart:
		return idx.insertLocked(ev)
	case EventInterim:
		idx.updateLocked(ev)
		return true
	case EventStop:
		idx.deleteKeyLocked(SessionKey{EndpointID: ev.EndpointID, AcctSessionID: ev.SessionID})
		return true
	case EventOn, EventOff:
		idx.flushLocked(ev)
		return true
	default:
		return true
	}
}

// LookupHandle returns a copy of the live record.
func (idx *SessionIndex) LookupHandle(handle string) (SessionRecord, bool) {
	if idx == nil || handle == "" {
		return SessionRecord{}, false
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	rec, ok := idx.byHandle[handle]
	if !ok {
		return SessionRecord{}, false
	}
	return cloneRecord(*rec), true
}

// LookupKey returns a copy by accounting identity.
func (idx *SessionIndex) LookupKey(key SessionKey) (SessionRecord, bool) {
	if idx == nil || key.AcctSessionID == "" {
		return SessionRecord{}, false
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	h, ok := idx.byKey[key]
	if !ok {
		return SessionRecord{}, false
	}
	rec, ok := idx.byHandle[h]
	if !ok {
		return SessionRecord{}, false
	}
	return cloneRecord(*rec), true
}

// List returns records with handle > cursor, sorted by handle, up to limit.
func (idx *SessionIndex) List(cursor string, limit int) []SessionRecord {
	if idx == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	handles := make([]string, 0, len(idx.byHandle))
	for h := range idx.byHandle {
		if h > cursor {
			handles = append(handles, h)
		}
	}
	sort.Strings(handles)
	if len(handles) > limit {
		handles = handles[:limit]
	}
	out := make([]SessionRecord, 0, len(handles))
	for _, h := range handles {
		out = append(out, cloneRecord(*idx.byHandle[h]))
	}
	return out
}

// Len is the live row count after expiry.
func (idx *SessionIndex) Len() int {
	if idx == nil {
		return 0
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	return len(idx.byHandle)
}

// FindDAS returns matching live rows for inbound DAS identification.
// n is 0 (miss), 1 (unique), or >1 (ambiguous).
func (idx *SessionIndex) FindDAS(q DASQuery) (SessionRecord, int) {
	if idx == nil {
		return SessionRecord{}, 0
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	var hits []SessionRecord
	for _, rec := range idx.byHandle {
		if rec == nil {
			continue
		}
		if q.ClientID != "" && rec.ClientID != q.ClientID {
			continue
		}
		if q.SessionID != "" && rec.Key.AcctSessionID != q.SessionID {
			continue
		}
		if q.UserID != "" && rec.UserID != q.UserID {
			continue
		}
		if q.NASIP.IsValid() && rec.NASIP.IsValid() && rec.NASIP != q.NASIP {
			continue
		}
		if q.NASIdentifier != "" && rec.NASIdentifier != q.NASIdentifier {
			continue
		}
		hits = append(hits, cloneRecord(*rec))
	}
	if len(hits) == 1 {
		return hits[0], 1
	}
	return SessionRecord{}, len(hits)
}

// StoreLastCoA records supported inbound CoA attrs on the index row.
func (idx *SessionIndex) StoreLastCoA(key SessionKey, attrs LastCoA) bool {
	if idx == nil || key.AcctSessionID == "" {
		return false
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	handle, ok := idx.byKey[key]
	if !ok {
		return false
	}
	rec := idx.byHandle[handle]
	if rec == nil {
		return false
	}
	idx.bytes -= rec.size()
	rec.LastCoA = cloneLastCoA(attrs)
	rec.LastUpdate = idx.clock.Now()
	idx.bytes += rec.size()
	return true
}

// Delete removes a live row by accounting identity.
func (idx *SessionIndex) Delete(key SessionKey) bool {
	if idx == nil || key.AcctSessionID == "" {
		return false
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.expireLocked(idx.clock.Now())
	if _, ok := idx.byKey[key]; !ok {
		return false
	}
	idx.deleteKeyLocked(key)
	return true
}

// Reset drops every row. runtime.reset and process exit wipe the table.
func (idx *SessionIndex) Reset() {
	if idx == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.byKey = map[SessionKey]string{}
	idx.byHandle = map[string]*SessionRecord{}
	idx.bytes = 0
	idx.setEntriesMetric(0)
}

func (idx *SessionIndex) insertLocked(ev AcctEvent) bool {
	if ev.SessionID == "" {
		return true
	}
	now := idx.clock.Now()
	key := SessionKey{EndpointID: ev.EndpointID, AcctSessionID: ev.SessionID}
	if handle, ok := idx.byKey[key]; ok {
		rec := idx.byHandle[handle]
		idx.bytes -= rec.size()
		idx.fill(rec, ev, now)
		rec.Handle = handle
		idx.bytes += rec.size()
		idx.setEntriesMetric(len(idx.byHandle))
		return true
	}
	rec := &SessionRecord{Handle: "", Key: key}
	idx.fill(rec, ev, now)
	n := rec.size()
	if len(idx.byHandle) >= idx.maxEntries || idx.bytes+n > idx.maxBytes {
		idx.metrics.RADIUSSessionIndexSaturation()
		return false
	}
	handle, err := idx.uniqueHandle(now)
	if err != nil {
		return false
	}
	rec.Handle = handle
	idx.byHandle[handle] = rec
	idx.byKey[key] = handle
	idx.bytes += rec.size()
	idx.setEntriesMetric(len(idx.byHandle))
	return true
}

func (idx *SessionIndex) updateLocked(ev AcctEvent) {
	if ev.SessionID == "" {
		return
	}
	handle, ok := idx.byKey[SessionKey{EndpointID: ev.EndpointID, AcctSessionID: ev.SessionID}]
	if !ok {
		return
	}
	rec := idx.byHandle[handle]
	idx.bytes -= rec.size()
	if ev.UserID != "" {
		rec.UserID = ev.UserID
	}
	if ev.NASIP.IsValid() {
		rec.NASIP = ev.NASIP
	}
	if ev.NASIdentifier != "" {
		rec.NASIdentifier = ev.NASIdentifier
	}
	if ev.NASPort != 0 {
		rec.NASPort = ev.NASPort
	}
	if ev.Peer.IsValid() {
		rec.Peer = ev.Peer
	}
	if len(ev.Class) > 0 {
		rec.Class = append([]byte(nil), ev.Class...)
	}
	rec.LastUpdate = idx.clock.Now()
	if ev.Revision != 0 {
		rec.Revision = ev.Revision
	}
	idx.bytes += rec.size()
}

func (idx *SessionIndex) uniqueHandle(now time.Time) (string, error) {
	for i := 0; i < 8; i++ {
		h, err := newULID(now, idx.entropy)
		if err != nil {
			return "", err
		}
		if _, exists := idx.byHandle[h]; !exists {
			return h, nil
		}
	}
	return "", domain.NewError(domain.CodeInternal, "session handle entropy exhausted")
}

func (idx *SessionIndex) deleteKeyLocked(key SessionKey) {
	if key.AcctSessionID == "" {
		return
	}
	handle, ok := idx.byKey[key]
	if !ok {
		return
	}
	if rec := idx.byHandle[handle]; rec != nil {
		idx.bytes -= rec.size()
	}
	delete(idx.byKey, key)
	delete(idx.byHandle, handle)
	idx.setEntriesMetric(len(idx.byHandle))
}

func (idx *SessionIndex) flushLocked(ev AcctEvent) {
	peerIP := ev.Peer.Addr()
	var drop []SessionKey
	for key, handle := range idx.byKey {
		if key.EndpointID != ev.EndpointID {
			continue
		}
		rec := idx.byHandle[handle]
		if rec == nil {
			drop = append(drop, key)
			continue
		}
		if matchesFlush(rec, peerIP, ev.NASIP, ev.NASIdentifier) {
			drop = append(drop, key)
		}
	}
	for _, key := range drop {
		idx.deleteKeyLocked(key)
	}
}

func matchesFlush(rec *SessionRecord, peerIP, nasIP netip.Addr, nasID string) bool {
	if rec == nil {
		return false
	}
	if peerIP.IsValid() && rec.Peer.IsValid() && rec.Peer.Addr() == peerIP {
		return true
	}
	if nasIP.IsValid() && rec.NASIP.IsValid() && rec.NASIP == nasIP {
		return true
	}
	if nasID != "" && rec.NASIdentifier == nasID {
		return true
	}
	return false
}

func (idx *SessionIndex) expireLocked(now time.Time) {
	var drop []SessionKey
	for _, rec := range idx.byHandle {
		if now.Sub(rec.LastUpdate) >= idx.ttl {
			drop = append(drop, rec.Key)
		}
	}
	for _, key := range drop {
		idx.deleteKeyLocked(key)
	}
}

func (idx *SessionIndex) fill(rec *SessionRecord, ev AcctEvent, now time.Time) {
	rec.Key = SessionKey{EndpointID: ev.EndpointID, AcctSessionID: ev.SessionID}
	rec.ClientID = ev.ClientID
	rec.EndpointID = ev.EndpointID
	rec.UserID = ev.UserID
	rec.NASIP = ev.NASIP
	rec.NASIdentifier = ev.NASIdentifier
	rec.NASPort = ev.NASPort
	rec.Peer = ev.Peer
	rec.Class = append([]byte(nil), ev.Class...)
	if !ev.StartedAt.IsZero() {
		rec.StartedAt = ev.StartedAt.UTC()
	} else if rec.StartedAt.IsZero() {
		rec.StartedAt = now
	}
	rec.LastUpdate = now
	rec.Revision = ev.Revision
}

func (idx *SessionIndex) setEntriesMetric(n int) {
	idx.metrics.SetRADIUSSessionIndexEntries(n)
}

func (r SessionRecord) size() int {
	n := 192
	n += len(r.Key.EndpointID) + len(r.Key.AcctSessionID)
	n += len(r.Handle) + len(r.ClientID) + len(r.UserID) + len(r.NASIdentifier)
	n += len(r.Class)
	for _, s := range r.LastCoA.ReplyMessage {
		n += len(s)
	}
	return n
}

func cloneRecord(in SessionRecord) SessionRecord {
	out := in
	if in.Class != nil {
		out.Class = append([]byte(nil), in.Class...)
	}
	out.LastCoA = cloneLastCoA(in.LastCoA)
	return out
}

func cloneLastCoA(in LastCoA) LastCoA {
	out := LastCoA{}
	if in.SessionTimeout != nil {
		v := *in.SessionTimeout
		out.SessionTimeout = &v
	}
	if in.IdleTimeout != nil {
		v := *in.IdleTimeout
		out.IdleTimeout = &v
	}
	if in.ReplyMessage != nil {
		out.ReplyMessage = append([]string(nil), in.ReplyMessage...)
	}
	return out
}

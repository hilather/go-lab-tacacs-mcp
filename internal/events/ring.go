package events

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

const (
	defaultCapacity     = 10000
	defaultStdoutBuffer = 256
	defaultSubBuffer    = 16
	DefaultLimit        = 50
	MaxLimit            = 200
	SchemaVersion       = 1
)

// Event categories stored in the ring.
const (
	CategoryAuthen   = "authen"
	CategoryAuthor   = "author"
	CategoryAcct     = "acct"
	CategoryConfig   = "config"
	CategoryToken    = "token"
	CategoryListener = "listener"
	CategorySystem   = "system"
	CategoryAPI      = "api"
	CategorySecurity = "security"
)

// Event is one redacted-at-read ring entry. Secrets are never stored.
type Event struct {
	SchemaVersion int             `json:"schema_version"`
	ID            uint64          `json:"id"`
	Time          time.Time       `json:"time"`
	Category      string          `json:"category"`
	Type          string          `json:"type"`
	Result        string          `json:"result"`
	Transport     string          `json:"transport,omitempty"`
	ClientID      string          `json:"client_id,omitempty"`
	SessionID     uint32          `json:"session_id,omitempty"`
	Revision      domain.Revision `json:"revision,omitempty"`
	UserID        string          `json:"user_id,omitempty"`
	Command       string          `json:"command,omitempty"`
	TaskID        string          `json:"task_id,omitempty"`
	Arguments     []EventAV       `json:"arguments,omitempty"`
	StartTime     *time.Time      `json:"start_time,omitempty"`
	StopTime      *time.Time      `json:"stop_time,omitempty"`
	AuthenMethod  string          `json:"authen_method,omitempty"`
	AuthenType    string          `json:"authen_type,omitempty"`
	Service       string          `json:"service,omitempty"`
	Privilege     uint8           `json:"privilege,omitempty"`
	Port          string          `json:"port,omitempty"`
	Remote        string          `json:"remote,omitempty"`
	// RADIUS-only additive fields. TACACS events leave them empty so JSON stays stable.
	// AcctSessionID is RADIUS Acct-Session-Id text; do not stuff it into SessionID.
	Protocol      string `json:"protocol,omitempty"`
	Carrier       string `json:"carrier,omitempty"`
	ListenerRole  string `json:"listener_role,omitempty"`
	ListenerID    string `json:"listener_id,omitempty"`
	PacketCode    string `json:"packet_code,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	EndpointID    string `json:"endpoint_id,omitempty"`
	AcctSessionID string `json:"acct_session_id,omitempty"`
	// SuppressExport keeps the record in the ring (accounting ACK) but hides
	// it from cursor reads, stdout, and fan-out when include_accounting is off.
	SuppressExport bool `json:"-"`
}

// EventAV is one stored attribute-value pair.
type EventAV struct {
	Name      string `json:"name"`
	Separator string `json:"separator"`
	Value     string `json:"value"`
}

// Query is a cursor page read. Optional Protocol, ListenerRole, PacketCode,
// and Outcome are ANDed with Categories. Empty strings match any value.
// Protocol "tacacs" also matches events that omit Protocol (JSON-stable TACACS).
// There is no filter-by-acct_session_id (cardinality / redaction).
type Query struct {
	AfterID      uint64
	Limit        int
	Categories   []string
	Protocol     string
	ListenerRole string
	PacketCode   string
	Outcome      string
}

// Page is one cursor window over retained events.
type Page struct {
	Items       []Event
	NextAfterID uint64
	HasMore     bool
	Reset       bool
	Overwritten uint64
	OldestID    uint64
	NewestID    uint64
}

// Options construct a ring, optional stdout sink, and fan-out.
type Options struct {
	Capacity        int
	Clock           domain.Clock
	Stdout          io.Writer
	RedactUserInput bool
	StdoutBuffer    int
	Metrics         *observability.Recorder
}

// Ring is a bounded, overwrite-oldest event sink. It is safe for concurrent use.
type Ring struct {
	mu            sync.Mutex
	clock         domain.Clock
	cap           int
	seq           uint64
	buf           []Event
	start         int
	n             int
	overwritten   uint64
	reject        atomic.Bool
	stdout        io.Writer
	redactUser    bool
	stdoutCh      chan Event
	stdoutDropped atomic.Uint64
	subs          []subscriber
	stop          chan struct{}
	closed        bool
	metrics       *observability.Recorder
}

// subscriber is one fan-out slot. The event channel is never closed while
// Accept may still send; slow consumers are detached and drop is closed.
type subscriber struct {
	ch   chan Event
	drop chan struct{}
	once *sync.Once
}

func (s subscriber) signalDrop() {
	if s.once == nil {
		return
	}
	s.once.Do(func() { close(s.drop) })
}

// New returns a ring with capacity entries. Capacity <= 0 uses 10_000.
func New(capacity int, clock domain.Clock) *Ring {
	return NewWithOptions(Options{Capacity: capacity, Clock: clock})
}

// NewWithOptions constructs a ring and, when Stdout is set, an async JSON sink.
func NewWithOptions(opts Options) *Ring {
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	clock := opts.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}
	r := &Ring{
		clock:      clock,
		cap:        capacity,
		buf:        make([]Event, capacity),
		stdout:     opts.Stdout,
		redactUser: opts.RedactUserInput,
		stop:       make(chan struct{}),
		metrics:    opts.Metrics,
	}
	if opts.Stdout != nil {
		buf := opts.StdoutBuffer
		if buf <= 0 {
			buf = defaultStdoutBuffer
		}
		r.stdoutCh = make(chan Event, buf)
		go r.stdoutLoop()
	}
	return r
}

// SetReject makes Accept return a zero Event without storing. Used for sink-fault tests.
func (r *Ring) SetReject(v bool) {
	if r == nil {
		return
	}
	r.reject.Store(v)
}

// Accept assigns an ID and timestamp and stores e. The stored copy is returned.
// A zero ID means the record was not accepted (nil ring or injected reject).
func (r *Ring) Accept(e Event) Event {
	if r == nil || r.reject.Load() {
		return Event{}
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Event{}
	}
	r.seq++
	e.ID = r.seq
	if e.SchemaVersion == 0 {
		e.SchemaVersion = SchemaVersion
	}
	if e.Time.IsZero() {
		e.Time = r.clock.Now().UTC()
	}
	if r.n == r.cap {
		r.buf[r.start] = e
		r.start = (r.start + 1) % r.cap
		r.overwritten++
		r.metrics.EventOverwritten(1)
	} else {
		r.buf[(r.start+r.n)%r.cap] = e
		r.n++
	}
	outCh := r.stdoutCh
	subs := append([]subscriber(nil), r.subs...)
	r.mu.Unlock()
	r.emitStdout(outCh, e)
	r.fanout(subs, e)
	return e
}

// Len is the number of retained events.
func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// Overwritten is how many events were dropped because the ring was full.
func (r *Ring) Overwritten() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.overwritten
}

// StdoutDropped is how many stdout JSON lines were dropped under backpressure.
func (r *Ring) StdoutDropped() uint64 {
	if r == nil {
		return 0
	}
	return r.stdoutDropped.Load()
}

// Latest returns the most recently accepted event, if any.
func (r *Ring) Latest() (Event, bool) {
	if r == nil {
		return Event{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == 0 {
		return Event{}, false
	}
	idx := (r.start + r.n - 1) % r.cap
	return r.buf[idx], true
}

// Snapshot returns retained events in id order (oldest first).
func (r *Ring) Snapshot() []Event {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, r.n)
	for i := 0; i < r.n; i++ {
		out[i] = r.buf[(r.start+i)%r.cap]
	}
	return out
}

// Read returns a cursor page. AfterID is exclusive. An evicted cursor sets Reset.
func (r *Ring) Read(q Query) Page {
	if r == nil {
		return Page{}
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	want := categorySet(q.Categories)
	r.mu.Lock()
	defer r.mu.Unlock()
	page := Page{Overwritten: r.overwritten}
	if r.n == 0 {
		return page
	}
	oldest := r.buf[r.start].ID
	newest := r.buf[(r.start+r.n-1)%r.cap].ID
	page.OldestID = oldest
	page.NewestID = newest
	if q.AfterID > 0 && oldest > 1 && q.AfterID < oldest-1 {
		page.Reset = true
	}
	out := make([]Event, 0, limit)
	for i := 0; i < r.n && len(out) < limit; i++ {
		ev := r.buf[(r.start+i)%r.cap]
		if ev.ID <= q.AfterID || ev.SuppressExport {
			continue
		}
		if !queryMatch(q, want, ev) {
			continue
		}
		out = append(out, ev)
	}
	page.Items = out
	if len(out) > 0 {
		page.NextAfterID = out[len(out)-1].ID
	} else {
		page.NextAfterID = q.AfterID
	}
	// HasMore if any retained event after the last returned item matches the filter.
	last := page.NextAfterID
	for i := 0; i < r.n; i++ {
		ev := r.buf[(r.start+i)%r.cap]
		if ev.ID <= last || ev.SuppressExport {
			continue
		}
		if queryMatch(q, want, ev) {
			page.HasMore = true
			break
		}
	}
	return page
}

// Subscribe receives new events on a bounded channel. A full queue detaches
// the subscriber and closes dropped; Accept never blocks on it. The event
// channel is not closed on drop (another Accept may still hold a copy).
func (r *Ring) Subscribe(buf int) (events <-chan Event, dropped <-chan struct{}, cancel func()) {
	if r == nil {
		ch := make(chan Event)
		done := make(chan struct{})
		close(ch)
		close(done)
		return ch, done, func() {}
	}
	if buf <= 0 {
		buf = defaultSubBuffer
	}
	sub := subscriber{
		ch:   make(chan Event, buf),
		drop: make(chan struct{}),
		once: &sync.Once{},
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		close(sub.ch)
		sub.signalDrop()
		return sub.ch, sub.drop, func() {}
	}
	r.subs = append(r.subs, sub)
	n := len(r.subs)
	r.mu.Unlock()
	r.metrics.SetEventSubscribers(n)
	var once sync.Once
	cancel = func() {
		once.Do(func() { r.unsubscribe(sub.ch) })
	}
	return sub.ch, sub.drop, cancel
}

// Close stops the stdout loop and subscriber fan-out. Accept after Close is rejected.
func (r *Ring) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.stop)
	subs := r.subs
	r.subs = nil
	r.mu.Unlock()
	for _, s := range subs {
		s.signalDrop()
	}
}

func (r *Ring) emitStdout(ch chan Event, e Event) {
	if ch == nil || e.SuppressExport {
		return
	}
	select {
	case <-r.stop:
		return
	case ch <- e:
	default:
		r.stdoutDropped.Add(1)
	}
}

func (r *Ring) stdoutLoop() {
	for {
		select {
		case <-r.stop:
			return
		case e, ok := <-r.stdoutCh:
			if !ok {
				return
			}
			_ = WriteJSON(r.stdout, e, r.redactUser)
		}
	}
}

func (r *Ring) fanout(subs []subscriber, e Event) {
	if e.SuppressExport {
		return
	}
	for _, sub := range subs {
		select {
		case sub.ch <- e:
		default:
			// Drop the slow subscriber. Do not close the event channel:
			// another Accept may still hold a copy of this slice and send.
			r.detach(sub.ch)
			sub.signalDrop()
			r.metrics.EventSubscriberReset()
		}
	}
}

func (r *Ring) unsubscribe(ch chan Event) {
	r.detach(ch)
}

func (r *Ring) detach(ch chan Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.subs {
		if s.ch == ch {
			r.subs = append(r.subs[:i], r.subs[i+1:]...)
			n := len(r.subs)
			r.mu.Unlock()
			r.metrics.SetEventSubscribers(n)
			r.mu.Lock()
			return
		}
	}
}

func categorySet(cats []string) map[string]struct{} {
	if len(cats) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(cats))
	for _, c := range cats {
		if c != "" {
			out[c] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func categoryOK(want map[string]struct{}, got string) bool {
	if want == nil {
		return true
	}
	_, ok := want[got]
	return ok
}

func queryMatch(q Query, wantCats map[string]struct{}, ev Event) bool {
	if !categoryOK(wantCats, ev.Category) {
		return false
	}
	if q.Protocol != "" {
		got := ev.Protocol
		if got == "" {
			// TACACS events omit Protocol so JSON stays stable.
			got = "tacacs"
		}
		if got != q.Protocol {
			return false
		}
	}
	if q.ListenerRole != "" && ev.ListenerRole != q.ListenerRole {
		return false
	}
	if q.PacketCode != "" && ev.PacketCode != q.PacketCode {
		return false
	}
	if q.Outcome != "" && ev.Outcome != q.Outcome {
		return false
	}
	return true
}

// RedactedAV is a stored attribute whose value must never appear in list views
// without events:sensitive (and is never a secret even then).
func RedactedAV(name string) EventAV {
	return EventAV{Name: name, Separator: "", Value: RedactedValue}
}

// CloneEvent copies e including argument slices.
func CloneEvent(e Event) Event {
	if len(e.Arguments) > 0 {
		e.Arguments = append([]EventAV(nil), e.Arguments...)
	}
	if e.StartTime != nil {
		t := *e.StartTime
		e.StartTime = &t
	}
	if e.StopTime != nil {
		t := *e.StopTime
		e.StopTime = &t
	}
	return e
}

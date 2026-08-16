package runtime

import (
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func testIndex(t *testing.T, opts Options) *SessionIndex {
	t.Helper()
	if opts.Entropy == nil {
		opts.Entropy = strings.NewReader(strings.Repeat("0123456789abcdef", 64))
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	idx, err := NewSessionIndex(opts)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func startEv(session string) AcctEvent {
	return AcctEvent{
		Kind:          EventStart,
		EndpointID:    "acct-udp",
		ClientID:      "lab-switches",
		UserID:        "lab-admin",
		SessionID:     session,
		NASIP:         netip.MustParseAddr("192.0.2.10"),
		NASIdentifier: "nas-1",
		NASPort:       3,
		Peer:          netip.MustParseAddrPort("192.0.2.10:1813"),
		Class:         []byte("class-secret"),
		StartedAt:     time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		Revision:      7,
	}
}

func TestSessionIndexStartInterimStop(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	if !idx.Apply(startEv("00000001")) {
		t.Fatal("start insert")
	}
	got, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "00000001"})
	if !ok || got.UserID != "lab-admin" || got.ClientID != "lab-switches" || got.Handle == "" {
		t.Fatalf("lookup=%+v ok=%v", got, ok)
	}
	if string(got.Class) != "class-secret" {
		t.Fatalf("class=%q", got.Class)
	}
	byHandle, ok := idx.LookupHandle(got.Handle)
	if !ok || byHandle.Key.AcctSessionID != "00000001" {
		t.Fatalf("handle=%+v ok=%v", byHandle, ok)
	}

	interim := startEv("00000001")
	interim.Kind = EventInterim
	interim.UserID = "lab-admin"
	if !idx.Apply(interim) {
		t.Fatal("interim")
	}
	updated, _ := idx.LookupHandle(got.Handle)
	if updated.LastUpdate.Before(got.LastUpdate) && !updated.LastUpdate.Equal(got.LastUpdate) {
		t.Fatalf("last_update did not move: %v -> %v", got.LastUpdate, updated.LastUpdate)
	}

	stop := startEv("00000001")
	stop.Kind = EventStop
	if !idx.Apply(stop) {
		t.Fatal("stop")
	}
	if _, ok := idx.LookupHandle(got.Handle); ok {
		t.Fatal("stop must delete")
	}
	if idx.Len() != 0 {
		t.Fatalf("len=%d", idx.Len())
	}
}

func TestSessionIndexStartReplaceKeepsHandle(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	if !idx.Apply(startEv("s1")) {
		t.Fatal("first")
	}
	first, _ := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "s1"})
	again := startEv("s1")
	again.UserID = "other"
	if !idx.Apply(again) {
		t.Fatal("replace")
	}
	got, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "s1"})
	if !ok || got.Handle != first.Handle || got.UserID != "other" {
		t.Fatalf("replace=%+v first=%+v", got, first)
	}
	if idx.Len() != 1 {
		t.Fatalf("len=%d", idx.Len())
	}
}

func TestSessionIndexStartWithoutSessionIDDoesNotInsert(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	ev := startEv("")
	if !idx.Apply(ev) {
		t.Fatal("ambiguous start is not a failure")
	}
	if idx.Len() != 0 {
		t.Fatalf("len=%d", idx.Len())
	}
}

func TestSessionIndexOnOffFlushByPeerOrNAS(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	a := startEv("a")
	b := startEv("b")
	b.Peer = netip.MustParseAddrPort("198.51.100.9:1813")
	b.NASIP = netip.MustParseAddr("198.51.100.9")
	b.NASIdentifier = "other-nas"
	c := startEv("c")
	c.EndpointID = "other-ep"
	if !idx.Apply(a) || !idx.Apply(b) || !idx.Apply(c) {
		t.Fatal("starts")
	}

	on := AcctEvent{
		Kind:       EventOn,
		EndpointID: "acct-udp",
		Peer:       netip.MustParseAddrPort("192.0.2.10:1813"),
	}
	if !idx.Apply(on) {
		t.Fatal("on")
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "a"}); ok {
		t.Fatal("peer match must flush a")
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "b"}); !ok {
		t.Fatal("b has a different peer/NAS and must remain")
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "other-ep", AcctSessionID: "c"}); !ok {
		t.Fatal("other endpoint must stay")
	}

	off := AcctEvent{
		Kind:          EventOff,
		EndpointID:    "acct-udp",
		NASIdentifier: "other-nas",
	}
	if !idx.Apply(off) {
		t.Fatal("off")
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "b"}); ok {
		t.Fatal("NAS-Identifier flush must delete b")
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "other-ep", AcctSessionID: "c"}); !ok {
		t.Fatal("other endpoint still stays")
	}
}

func TestSessionIndexOnFlushesByNASIP(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	if !idx.Apply(startEv("s")) {
		t.Fatal("start")
	}
	on := AcctEvent{
		Kind:       EventOn,
		EndpointID: "acct-udp",
		Peer:       netip.MustParseAddrPort("203.0.113.1:9"),
		NASIP:      netip.MustParseAddr("192.0.2.10"),
	}
	if !idx.Apply(on) {
		t.Fatal("on")
	}
	if idx.Len() != 0 {
		t.Fatalf("NAS-IP flush left %d", idx.Len())
	}
}

func TestSessionIndexSaturationRefusesInsert(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry()
	rec := observability.NewRecorder(reg)
	idx := testIndex(t, Options{MaxEntries: 1, MaxBytes: 8 << 20, TTL: time.Hour, Metrics: rec})
	if !idx.Apply(startEv("one")) {
		t.Fatal("first")
	}
	if idx.Apply(startEv("two")) {
		t.Fatal("second insert must saturate")
	}
	if idx.Len() != 1 {
		t.Fatalf("len=%d", idx.Len())
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "one"}); !ok {
		t.Fatal("existing row stays")
	}
	stop := startEv("one")
	stop.Kind = EventStop
	if !idx.Apply(stop) {
		t.Fatal("stop still works")
	}
}

func TestSessionIndexByteSaturation(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 100, MaxBytes: 400, TTL: time.Hour})
	if !idx.Apply(startEv("tiny")) {
		t.Fatal("first")
	}
	fat := startEv("fat")
	fat.Class = make([]byte, 512)
	if idx.Apply(fat) {
		t.Fatal("byte cap must refuse")
	}
}

func TestSessionIndexTTLExpiry(t *testing.T) {
	t.Parallel()
	clk := &fixedClock{t: time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)}
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Minute, Clock: clk})
	if !idx.Apply(startEv("exp")) {
		t.Fatal("start")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "exp"}); ok {
		t.Fatal("expired row must be gone")
	}
	if idx.Len() != 0 {
		t.Fatalf("len=%d", idx.Len())
	}
}

func TestSessionIndexResetWipes(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	if !idx.Apply(startEv("s")) {
		t.Fatal("start")
	}
	idx.Reset()
	if idx.Len() != 0 {
		t.Fatalf("len=%d", idx.Len())
	}
	if _, ok := idx.LookupKey(SessionKey{EndpointID: "acct-udp", AcctSessionID: "s"}); ok {
		t.Fatal("reset must drop handle")
	}
}

func TestSessionIndexListDeterministicAndRedactedClass(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	for _, id := range []string{"z", "a", "m"} {
		if !idx.Apply(startEv(id)) {
			t.Fatal(id)
		}
	}
	page := idx.List("", 10)
	if len(page) != 3 {
		t.Fatalf("len=%d", len(page))
	}
	for i := 1; i < len(page); i++ {
		if page[i-1].Handle > page[i].Handle {
			t.Fatalf("not sorted: %q then %q", page[i-1].Handle, page[i].Handle)
		}
	}
	again := idx.List("", 10)
	if page[0].Handle != again[0].Handle || page[2].Handle != again[2].Handle {
		t.Fatal("list order unstable")
	}
}

func TestSessionIndexCursorPage(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	for _, id := range []string{"1", "2", "3"} {
		if !idx.Apply(startEv(id)) {
			t.Fatal(id)
		}
	}
	first := idx.List("", 2)
	if len(first) != 2 {
		t.Fatalf("first=%d", len(first))
	}
	rest := idx.List(first[1].Handle, 2)
	if len(rest) != 1 {
		t.Fatalf("rest=%d", len(rest))
	}
	if rest[0].Handle <= first[1].Handle {
		t.Fatalf("cursor=%q rest=%q", first[1].Handle, rest[0].Handle)
	}
}

func TestSessionIndexAccessAcceptNeverImplied(t *testing.T) {
	t.Parallel()
	idx := testIndex(t, Options{MaxEntries: 16, MaxBytes: 64 << 10, TTL: time.Hour})
	// Access-Accept is not an accounting kind. Unknown kinds are ignored.
	ev := startEv("acc")
	ev.Kind = "access_accept"
	if !idx.Apply(ev) {
		t.Fatal("unknown kind is not an error")
	}
	if idx.Len() != 0 {
		t.Fatal("Access-Accept must not insert")
	}
}

func TestNewSessionIndexRequiresCaps(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionIndex(Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewULID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	a, err := newULID(now, strings.NewReader(strings.Repeat("a", 32)))
	if err != nil || len(a) != 26 {
		t.Fatalf("ulid=%q err=%v", a, err)
	}
	b, err := newULID(now, strings.NewReader(strings.Repeat("b", 32)))
	if err != nil || a == b {
		t.Fatalf("a=%q b=%q", a, b)
	}
	if _, err := newULID(now, io.LimitReader(strings.NewReader("x"), 1)); err == nil {
		t.Fatal("short entropy")
	}
}

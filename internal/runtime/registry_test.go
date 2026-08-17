package runtime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestNewRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	_, err := New(
		newStub("a", "127.0.0.1:1", domain.CarrierTACACSLegacyTCP),
		newStub("a", "127.0.0.1:2", domain.CarrierTACACSLegacyTCP),
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate listener id") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsBindConflict(t *testing.T) {
	t.Parallel()
	_, err := New(
		newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP),
		newStub("secure_tacacs", "127.0.0.1:4949", domain.CarrierTACACSTLS),
	)
	if err == nil || !strings.Contains(err.Error(), "bind conflict") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsWildcardSamePort(t *testing.T) {
	t.Parallel()
	_, err := New(
		newStub("legacy_tacacs", "0.0.0.0:4949", domain.CarrierTACACSLegacyTCP),
		newStub("secure_tacacs", "127.0.0.1:4949", domain.CarrierTACACSTLS),
	)
	if err == nil || !strings.Contains(err.Error(), "bind conflict") {
		t.Fatalf("got %v", err)
	}
}

func TestNewAllowsEphemeralSameHost(t *testing.T) {
	t.Parallel()
	reg, err := New(
		newStub("legacy_tacacs", "127.0.0.1:0", domain.CarrierTACACSLegacyTCP),
		newStub("secure_tacacs", "127.0.0.1:0", domain.CarrierTACACSTLS),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 2 {
		t.Fatalf("len=%d", reg.Len())
	}
}

func TestNewAllowsSamePortDifferentNetwork(t *testing.T) {
	t.Parallel()
	_, err := New(
		newStub("legacy_tacacs", "127.0.0.1:1812", domain.CarrierTACACSLegacyTCP),
		newStub("radius_access", "127.0.0.1:1812", domain.CarrierRADIUSUDP),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsEmptyIDAndBind(t *testing.T) {
	t.Parallel()
	if _, err := New(newStub("", "127.0.0.1:1", domain.CarrierTACACSLegacyTCP)); err == nil {
		t.Fatal("expected empty id")
	}
	if _, err := New(newStub("legacy_tacacs", "", domain.CarrierTACACSLegacyTCP)); err == nil {
		t.Fatal("expected empty bind")
	}
	if _, err := New(newStub("legacy_tacacs", "not-a-bind", domain.CarrierTACACSLegacyTCP)); err == nil {
		t.Fatal("expected invalid bind")
	}
}

func TestStartLaunchesSortedAndDrainReverse(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var drained []string
	a := newStub("secure_tacacs", "127.0.0.1:4300", domain.CarrierTACACSTLS)
	b := newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP)
	a.onDrain = func() {
		mu.Lock()
		drained = append(drained, a.id)
		mu.Unlock()
	}
	b.onDrain = func() {
		mu.Lock()
		drained = append(drained, b.id)
		mu.Unlock()
	}
	reg, err := New(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(reg.Statuses()); strings.Join(got, ",") != "legacy_tacacs,secure_tacacs" {
		t.Fatalf("sorted=%v", got)
	}
	if reg.Get("legacy_tacacs") != b || reg.Get("missing") != nil {
		t.Fatal("Get")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, reg.Len())
	if err := reg.Start(ctx, errc); err != nil {
		t.Fatal(err)
	}
	waitReady(t, a, b)

	if err := reg.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotDrain := append([]string(nil), drained...)
	mu.Unlock()
	if strings.Join(gotDrain, ",") != "secure_tacacs,legacy_tacacs" {
		t.Fatalf("drain order %v", gotDrain)
	}

	cancel()
	for i := 0; i < reg.Len(); i++ {
		select {
		case <-errc:
		case <-time.After(time.Second):
			t.Fatal("start did not return")
		}
	}
}

func TestReadyRequiresRequiredListener(t *testing.T) {
	t.Parallel()
	l := newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP)
	l.required = true
	reg, err := New(l)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Ready() {
		t.Fatal("not started must not be ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	if err := reg.Start(ctx, errc); err != nil {
		t.Fatal(err)
	}
	waitReady(t, l)
	if !reg.Ready() {
		t.Fatal("required listener running")
	}
	if !reg.HasProtocol(domain.ProtocolTACACS) {
		t.Fatal("HasProtocol tacacs")
	}
	if reg.HasProtocol(domain.ProtocolRADIUS) {
		t.Fatal("no RADIUS listener registered")
	}
	if !reg.HasReadyAAA() {
		t.Fatal("HasReadyAAA")
	}
	cancel()
}

func TestHasReadyAAAIgnoresDynAuth(t *testing.T) {
	t.Parallel()
	l := newStub("radius_dynauth", "127.0.0.1:3799", domain.CarrierRADIUSUDP)
	l.role = domain.RoleDynamicAuthorization
	reg, err := New(l)
	if err != nil {
		t.Fatal(err)
	}
	l.ready.Store(true)
	if !l.Ready() {
		t.Fatal("dynauth ready")
	}
	if reg.HasReadyAAA() {
		t.Fatal("ready dynauth is not AAA")
	}
}

func TestHasReadyAAAFalseWhenEmpty(t *testing.T) {
	t.Parallel()
	if (&Registry{}).HasReadyAAA() {
		t.Fatal("empty")
	}
	l := newStub("radius_access", "127.0.0.1:1812", domain.CarrierRADIUSUDP)
	reg, err := New(l)
	if err != nil {
		t.Fatal(err)
	}
	if reg.HasReadyAAA() {
		t.Fatal("not started")
	}
}

func TestStartRejectsNilErrcAndDoubleStart(t *testing.T) {
	t.Parallel()
	reg, err := New(newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Start(context.Background(), nil); err == nil {
		t.Fatal("expected nil errc")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	if err := reg.Start(ctx, errc); err != nil {
		t.Fatal(err)
	}
	if err := reg.Start(ctx, errc); err == nil {
		t.Fatal("expected double start")
	}
	cancel()
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	l := newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP)
	reg, err := New(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reg.Close(); err != nil {
		t.Fatal(err)
	}
	if l.closes.Load() < 1 {
		t.Fatal("close not delegated")
	}
}

func TestDrainSurfacesFirstError(t *testing.T) {
	t.Parallel()
	boom := errors.New("drain failed")
	a := newStub("legacy_tacacs", "127.0.0.1:4949", domain.CarrierTACACSLegacyTCP)
	b := newStub("secure_tacacs", "127.0.0.1:4300", domain.CarrierTACACSTLS)
	b.drainErr = boom
	reg, err := New(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Drain(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

type stubListener struct {
	id       string
	bind     string
	carrier  domain.Carrier
	role     domain.ListenerRole
	required bool
	ready    atomic.Bool
	closes   atomic.Int32
	drainErr error
	onStart  func()
	onDrain  func()
	started  chan struct{}
}

func newStub(id, bind string, carrier domain.Carrier) *stubListener {
	return &stubListener{
		id:      id,
		bind:    bind,
		carrier: carrier,
		started: make(chan struct{}),
	}
}

func (s *stubListener) ID() string { return s.id }
func (s *stubListener) Protocol() domain.Protocol {
	if s.carrier == domain.CarrierRADIUSUDP {
		return domain.ProtocolRADIUS
	}
	return domain.ProtocolTACACS
}
func (s *stubListener) Carrier() domain.Carrier { return s.carrier }
func (s *stubListener) Role() domain.ListenerRole {
	if s.role != "" {
		return s.role
	}
	if s.carrier == domain.CarrierRADIUSUDP {
		return domain.RoleAccess
	}
	return domain.RoleAAA
}
func (s *stubListener) Ready() bool { return s.ready.Load() }

func (s *stubListener) Status() Status {
	return Status{
		Descriptor: Descriptor{
			ID:       s.id,
			Protocol: s.Protocol(),
			Carrier:  s.carrier,
			Roles:    []domain.ListenerRole{s.Role()},
			Bind:     s.bind,
			Required: s.required,
		},
		Enabled: true,
		Ready:   s.ready.Load(),
	}
}

func (s *stubListener) Start(ctx context.Context) error {
	s.ready.Store(true)
	if s.onStart != nil {
		s.onStart()
	}
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	<-ctx.Done()
	s.ready.Store(false)
	return nil
}

func (s *stubListener) Drain(context.Context) error {
	s.ready.Store(false)
	if s.onDrain != nil {
		s.onDrain()
	}
	return s.drainErr
}

func (s *stubListener) Close() error {
	s.closes.Add(1)
	s.ready.Store(false)
	return nil
}

func waitReady(t *testing.T, ls ...*stubListener) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for _, l := range ls {
		select {
		case <-l.started:
		case <-time.After(time.Until(deadline)):
			t.Fatalf("%s did not start", l.id)
		}
	}
}

func idsOf(sts []Status) []string {
	out := make([]string, len(sts))
	for i, st := range sts {
		out[i] = st.ID
	}
	return out
}

var _ Listener = (*stubListener)(nil)

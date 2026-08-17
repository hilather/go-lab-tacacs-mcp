package runtime

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// BindKind is the Challenge State bind tagged union.
type BindKind uint8

const (
	// BindUDPIP binds a continuation to the UDP source IP (not port).
	BindUDPIP BindKind = iota
	// BindTLSCert binds a continuation to SHA-256(peer certificate DER).
	BindTLSCert
)

func (k BindKind) String() string {
	switch k {
	case BindUDPIP:
		return "udp_ip"
	case BindTLSCert:
		return "tls_cert"
	default:
		return "unknown"
	}
}

// ChallengeBind is the carrier-specific continuation constraint.
// UDP uses SourceIP only. TLS uses CertFP only (TCP peer IP is not part of the bind).
type ChallengeBind struct {
	Kind     BindKind
	SourceIP netip.Addr // BindUDPIP
	CertFP   [32]byte   // BindTLSCert; SHA-256 of raw peer certificate
}

// Unset reports a zero bind that IssueChallenge may fill from the request.
func (b ChallengeBind) Unset() bool {
	return !b.SourceIP.IsValid() && b.CertFP == [32]byte{}
}

func (b ChallengeBind) match(other ChallengeBind) bool {
	if b.Kind != other.Kind {
		return false
	}
	switch b.Kind {
	case BindUDPIP:
		return b.SourceIP.IsValid() && b.SourceIP == other.SourceIP
	case BindTLSCert:
		return b.CertFP != [32]byte{} && b.CertFP == other.CertFP
	default:
		return false
	}
}

// ChallengeStep is the EAP conversation step stored on a pending State.
type ChallengeStep string

const (
	StepIdentity      ChallengeStep = "identity"
	StepMD5Challenge  ChallengeStep = "md5_challenge"
	StepPEAPStart     ChallengeStep = "peap_start"
	StepPEAPHandshake ChallengeStep = "peap_handshake"
	StepPEAPInner     ChallengeStep = "peap_inner"
	StepPEAPMSCHAP    ChallengeStep = "peap_mschap"
	StepPEAPFinish    ChallengeStep = "peap_finish"
	StepDone          ChallengeStep = "done"
)

// ChallengeIssue is the adapter-built insert. Raw State is hashed and is
// not retained on the record.
type ChallengeIssue struct {
	State        []byte
	EndpointID   string
	ClientID     string
	Bind         ChallengeBind
	UserID       string
	Method       string
	EAPID        byte
	EAPType      byte
	Step         ChallengeStep
	MD5Challenge []byte
	TunnelID     string
	Revision     domain.Revision
}

// String omits State, MD5 challenge, and certificate material.
func (in ChallengeIssue) String() string {
	return fmt.Sprintf("ChallengeIssue{endpoint=%s client=%s bind=%s step=%s}", in.EndpointID, in.ClientID, in.Bind.Kind, in.Step)
}

// GoString is the %#v form and never includes State or MD5 bytes.
func (in ChallengeIssue) GoString() string { return in.String() }

// Format never writes State or MD5 challenge bytes.
func (in ChallengeIssue) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, in.String())
}

// ChallengeRecord is a consumed (or inspected) store row. MD5Challenge is
// copied out and wiped from the store on a successful consume.
type ChallengeRecord struct {
	EndpointID   string
	ClientID     string
	Bind         ChallengeBind
	UserID       string
	Method       string
	EAPID        byte
	EAPType      byte
	Step         ChallengeStep
	MD5Challenge []byte
	TunnelID     string
	Expires      time.Time
	Revision     domain.Revision
}

// String omits State, MD5 challenge, and certificate material.
func (r ChallengeRecord) String() string {
	return fmt.Sprintf("ChallengeRecord{endpoint=%s client=%s bind=%s step=%s}", r.EndpointID, r.ClientID, r.Bind.Kind, r.Step)
}

// GoString is the %#v form and never includes MD5 or cert bytes.
func (r ChallengeRecord) GoString() string { return r.String() }

// Format never writes MD5 challenge or certificate material.
func (r ChallengeRecord) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.String())
}

// IssueResult is the insert outcome.
type IssueResult uint8

const (
	IssueOK IssueResult = iota
	IssueInvalid
	IssueExists
	IssueSaturated
)

// ConsumeResult is the lookup/consume outcome.
type ConsumeResult uint8

const (
	ConsumeOK ConsumeResult = iota
	ConsumeUnknown
	ConsumeExpired
	ConsumeBinding
)

type challengeEntry struct {
	endpointID string
	clientID   string
	bind       ChallengeBind
	userID     string
	method     string
	eapID      byte
	eapType    byte
	step       ChallengeStep
	md5        []byte
	tunnelID   string
	expires    time.Time
	revision   domain.Revision
	bytes      int
}

// ChallengeStore is the in-memory, consume-on-use Access-Challenge State table.
// Capacity is fail-closed: it never evicts an in-flight record to admit another.
type ChallengeStore struct {
	mu          sync.Mutex
	entries     map[[32]byte]*challengeEntry
	maxEntries  int
	maxBytes    int
	usedBytes   int
	ttl         time.Duration
	now         func() time.Time
	saturations atomic.Uint64
	onSaturate  func()
}

// NewChallengeStore builds a bounded store. Zero caps and TTL take the
// documented access-listener defaults. now is injectable; nil uses time.Now.
func NewChallengeStore(entries, bytes int, ttl time.Duration, now func() time.Time) *ChallengeStore {
	return NewChallengeStoreWithHook(entries, bytes, ttl, now, nil)
}

// NewChallengeStoreWithHook is NewChallengeStore plus a saturation hook
// (metrics). The hook must not retain State or other secrets.
func NewChallengeStoreWithHook(entries, bytes int, ttl time.Duration, now func() time.Time, onSaturate func()) *ChallengeStore {
	if entries <= 0 {
		entries = 4096
	}
	if bytes <= 0 {
		bytes = 1 << 20
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &ChallengeStore{
		entries:    make(map[[32]byte]*challengeEntry, entries),
		maxEntries: entries,
		maxBytes:   bytes,
		ttl:        ttl,
		now:        now,
		onSaturate: onSaturate,
	}
}

func challengeKey(endpointID string, state []byte) [32]byte {
	sum := sha256.New()
	_, _ = sum.Write([]byte(endpointID))
	_, _ = sum.Write(state)
	var out [32]byte
	copy(out[:], sum.Sum(nil))
	return out
}

func entryBytes(e *challengeEntry) int {
	if e == nil {
		return 0
	}
	return 32 + len(e.endpointID) + len(e.clientID) + len(e.userID) + len(e.method) + len(e.md5) + len(e.tunnelID) + 64
}

func (s *ChallengeStore) issueValid(in ChallengeIssue) bool {
	if len(in.State) == 0 || in.EndpointID == "" || in.ClientID == "" {
		return false
	}
	switch in.Bind.Kind {
	case BindUDPIP:
		return in.Bind.SourceIP.IsValid()
	case BindTLSCert:
		return in.Bind.CertFP != [32]byte{}
	default:
		return false
	}
}

// Issue inserts a new State record. It never overwrites an existing key and
// never evicts to make room. Saturated inserts increment Saturations.
func (s *ChallengeStore) Issue(in ChallengeIssue) IssueResult {
	if s == nil {
		return IssueSaturated
	}
	if !s.issueValid(in) {
		return IssueInvalid
	}
	key := challengeKey(in.EndpointID, in.State)
	now := s.now()
	var hook func()
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
	}()
	s.expireLocked(now)
	if _, exists := s.entries[key]; exists {
		return IssueExists
	}
	e := &challengeEntry{
		endpointID: in.EndpointID,
		clientID:   in.ClientID,
		bind:       in.Bind,
		userID:     in.UserID,
		method:     in.Method,
		eapID:      in.EAPID,
		eapType:    in.EAPType,
		step:       in.Step,
		md5:        append([]byte(nil), in.MD5Challenge...),
		tunnelID:   in.TunnelID,
		expires:    now.Add(s.ttl),
		revision:   in.Revision,
	}
	e.bytes = entryBytes(e)
	if len(s.entries) >= s.maxEntries || s.usedBytes+e.bytes > s.maxBytes {
		wipe(e.md5)
		s.saturations.Add(1)
		hook = s.onSaturate
		return IssueSaturated
	}
	s.entries[key] = e
	s.usedBytes += e.bytes
	return IssueOK
}

// Consume deletes a matching live record. Binding/client/endpoint mismatch
// does not consume (the legitimate peer may still continue). Replay after a
// successful consume is ConsumeUnknown.
func (s *ChallengeStore) Consume(endpointID string, state []byte, clientID string, bind ChallengeBind) (ChallengeRecord, ConsumeResult) {
	if s == nil || endpointID == "" || len(state) == 0 {
		return ChallengeRecord{}, ConsumeUnknown
	}
	key := challengeKey(endpointID, state)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return ChallengeRecord{}, ConsumeUnknown
	}
	if !e.expires.After(now) {
		s.removeLocked(key)
		return ChallengeRecord{}, ConsumeExpired
	}
	if e.clientID != clientID || !e.bind.match(bind) {
		return ChallengeRecord{}, ConsumeBinding
	}
	out := ChallengeRecord{
		EndpointID:   e.endpointID,
		ClientID:     e.clientID,
		Bind:         e.bind,
		UserID:       e.userID,
		Method:       e.method,
		EAPID:        e.eapID,
		EAPType:      e.eapType,
		Step:         e.step,
		MD5Challenge: append([]byte(nil), e.md5...),
		TunnelID:     e.tunnelID,
		Expires:      e.expires,
		Revision:     e.revision,
	}
	s.removeLocked(key)
	return out, ConsumeOK
}

// Reset wipes every record. Safe on a nil store.
func (s *ChallengeStore) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.entries {
		s.removeLocked(k)
	}
}

// Len is the number of live records after an expiry sweep.
func (s *ChallengeStore) Len() int {
	if s == nil {
		return 0
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	return len(s.entries)
}

// Saturations is the number of refused inserts.
func (s *ChallengeStore) Saturations() uint64 {
	if s == nil {
		return 0
	}
	return s.saturations.Load()
}

func (s *ChallengeStore) expireLocked(now time.Time) {
	for k, e := range s.entries {
		if !e.expires.After(now) {
			s.removeLocked(k)
		}
	}
}

func (s *ChallengeStore) removeLocked(key [32]byte) {
	e, ok := s.entries[key]
	if !ok {
		return
	}
	wipe(e.md5)
	s.usedBytes -= e.bytes
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
	delete(s.entries, key)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

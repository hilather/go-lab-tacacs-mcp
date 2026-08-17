package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

// RFC 2866 §5.1 Acct-Status-Type values recorded in MVP.
const (
	acctStatusStart   uint32 = 1
	acctStatusStop    uint32 = 2
	acctStatusInterim uint32 = 3
	acctStatusOn      uint32 = 7
	acctStatusOff     uint32 = 8
)

// RADIUSRecorder is the AAA sink. *aaa.Service implements it.
type RADIUSRecorder interface {
	RecordRADIUSAccounting(ctx context.Context, rec aaa.RADIUSAccountingRecord) (aaa.AccountingResult, error)
}

// SemanticJournal is the UDP accounting idempotency store (implemented by udp).
type SemanticJournal interface {
	Seen(JournalKey) bool
	Remember(JournalKey) bool
}

// AmbiguousSampler caps ring appends when identity is missing.
type AmbiguousSampler interface {
	Allow() bool
}

// JournalKey is the semantic accounting identity (design §5.5).
// event_fingerprint excludes Acct-Delay-Time, Identifier, Request
// Authenticator, and the whole-packet digest.
type JournalKey struct {
	EndpointID  string
	SrcIP       string
	SrcPort     uint16
	SessionID   string
	StatusType  string
	NAS         string
	Fingerprint [32]byte
}

// Accounting maps Accounting-Request onto RecordRADIUSAccounting.
type Accounting struct {
	AAA RADIUSRecorder
}

// Handle implements Handler for the accounting role.
func (a Accounting) Handle(ctx context.Context, in Request) Result {
	if ctx != nil && ctx.Err() != nil {
		return Result{Action: ActionDiscard, Reason: ReasonOverload}
	}
	if in.Role != domain.RoleAccounting {
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
	if in.Packet.Code != codec.CodeAccountingRequest {
		return Result{Action: ActionDiscard, Reason: ReasonInvalidCode}
	}
	if reason := CheckAccountingIntegrity(in.Secret, in.Declared, in.Packet); reason != "" {
		return Result{Action: ActionDiscard, Reason: reason}
	}

	kind, ok := mapAcctStatus(in.Packet.Attributes)
	if !ok || !statusAllowed(kind, in.AcceptStatusTypes) {
		return Result{Action: ActionDiscard, Reason: ReasonUnknownAcctStatus}
	}

	sessionID := textAttr(in.Packet.Attributes, attribute.TypeAcctSessionID)
	nas := nasIdentity(in.Packet.Attributes)
	key := JournalKey{
		EndpointID:  in.EndpointID,
		SrcIP:       in.Peer.Addr().String(),
		SrcPort:     in.Peer.Port(),
		SessionID:   sessionID,
		StatusType:  kind.String(),
		NAS:         nas,
		Fingerprint: eventFingerprint(kind, in.Packet.Attributes),
	}

	if in.Journal != nil && in.Journal.Seen(key) {
		return accountingReply(in, ReasonOK, false)
	}

	ambiguous := sessionID == "" && nas == ""
	if ambiguous && (in.Sampler == nil || !in.Sampler.Allow()) {
		// Fail-open-to-ack: still reply so the NAS does not retry-storm.
		// Remember the key so a Delay-Time retry cannot fill the ring
		// when the sample window resets.
		if in.Journal != nil {
			_ = in.Journal.Remember(key)
		}
		return accountingReply(in, ReasonAmbiguousIdentity, false)
	}

	if a.AAA == nil {
		return Result{Action: ActionDiscard, Reason: ReasonInternal}
	}
	rec := buildRADIUSRecord(in, kind, sessionID, key)
	res, err := a.AAA.RecordRADIUSAccounting(ctx, rec)
	if err != nil || !res.OK || res.EventID == 0 {
		return Result{Action: ActionDiscard, Reason: ReasonInternal}
	}

	saturated := false
	if in.Journal != nil && !in.Journal.Remember(key) {
		saturated = true
	}
	return accountingReply(in, ReasonOK, saturated)
}

// CheckAccountingIntegrity validates the Accounting-Request Authenticator
// and, when present, Message-Authenticator. Missing MA is allowed.
// Invalid or duplicate MA is a silent discard. This must run before
// retransmission-cache mutation.
func CheckAccountingIntegrity(secret []byte, declared []byte, pkt codec.Packet) string {
	if err := crypto.ValidateAccountingRequestAuthenticator(secret, declared); err != nil {
		return ReasonInvalidAcctAuth
	}
	found := pkt.Attributes.AllOf(attribute.TypeMessageAuthenticator)
	switch found.Len() {
	case 0:
		return ""
	case 1:
		if err := crypto.ValidateMessageAuthenticator(secret, declared); err != nil {
			return ReasonInvalidMA
		}
		return ""
	default:
		return ReasonInvalidMA
	}
}

func accountingReply(in Request, reason string, saturated bool) Result {
	wire, err := SignResponse(in.Secret, codec.CodeAccountingResponse, in.Packet.Identifier, in.Packet.Authenticator, CopyProxyState(in.Packet.Attributes))
	if err != nil {
		return Result{Action: ActionDiscard, Reason: ReasonMalformedHeader}
	}
	return Result{Action: ActionReply, Reason: reason, Response: wire, JournalSaturated: saturated}
}

func mapAcctStatus(attrs attribute.RawSet) (aaa.AccountingKind, bool) {
	found := attrs.AllOf(attribute.TypeAcctStatusType)
	if found.Len() != 1 {
		return "", false
	}
	v, ok := uint32Val(found[0])
	if !ok {
		return "", false
	}
	switch v {
	case acctStatusStart:
		return aaa.AccountingStart, true
	case acctStatusStop:
		return aaa.AccountingStop, true
	case acctStatusInterim:
		return aaa.AccountingInterim, true
	case acctStatusOn:
		return aaa.AccountingOn, true
	case acctStatusOff:
		return aaa.AccountingOff, true
	default:
		return "", false
	}
}

func statusAllowed(kind aaa.AccountingKind, allow []string) bool {
	if !kind.Valid() {
		return false
	}
	if len(allow) == 0 {
		return true
	}
	want := kind.String()
	for _, s := range allow {
		if s == want {
			return true
		}
	}
	return false
}

func buildRADIUSRecord(in Request, kind aaa.AccountingKind, sessionID string, key JournalKey) aaa.RADIUSAccountingRecord {
	attrs := in.Packet.Attributes
	rec := aaa.RADIUSAccountingRecord{
		Context: domain.RequestContext{
			Protocol:         domain.ProtocolRADIUS,
			Carrier:          requestCarrier(in),
			ListenerRole:     domain.RoleAccounting,
			ListenerID:       in.ListenerID,
			ClientID:         in.ClientID,
			EndpointID:       in.EndpointID,
			Peer:             in.Peer,
			SnapshotRevision: in.Revision,
		},
		Kind:           kind,
		UserID:         textAttr(attrs, attribute.TypeUserName),
		SessionID:      sessionID,
		SessionTime:    durationAttr(attrs, attribute.TypeAcctSessionTime),
		InputOctets:    foldedOctets(attrs, attribute.TypeAcctInputOctets, attribute.TypeAcctInputGigawords),
		OutputOctets:   foldedOctets(attrs, attribute.TypeAcctOutputOctets, attribute.TypeAcctOutputGigawords),
		TerminateCause: terminateCauseName(attrs),
		SafeAttributes: summarizeAttrs(attrs),
		IdempotencyKey: hex.EncodeToString(key.Fingerprint[:]),
	}
	if ts, ok := timeAttr(attrs, attribute.TypeEventTimestamp); ok {
		rec.StartedAt = &ts
	}
	return rec
}

func eventFingerprint(kind aaa.AccountingKind, attrs attribute.RawSet) [32]byte {
	h := sha256.New()
	if kind == aaa.AccountingInterim {
		// Interim identity includes counters and Event-Timestamp so
		// successive updates are not collapsed (design §5.5).
		writeTyped(h, attrs, attribute.TypeEventTimestamp)
		writeTyped(h, attrs, attribute.TypeAcctSessionTime)
		writeTyped(h, attrs, attribute.TypeAcctInputOctets)
		writeTyped(h, attrs, attribute.TypeAcctInputGigawords)
		writeTyped(h, attrs, attribute.TypeAcctOutputOctets)
		writeTyped(h, attrs, attribute.TypeAcctOutputGigawords)
		writeTyped(h, attrs, attribute.TypeAcctInputPackets)
		writeTyped(h, attrs, attribute.TypeAcctOutputPackets)
	} else {
		// Conservative: remaining attributes except delay-time, MA, Proxy-State.
		for _, a := range attrs {
			switch a.Type {
			case attribute.TypeAcctDelayTime, attribute.TypeMessageAuthenticator, attribute.TypeProxyState:
				continue
			}
			_, _ = h.Write([]byte{a.Type, byte(len(a.Value))})
			_, _ = h.Write(a.Value)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeTyped(h interface{ Write([]byte) (int, error) }, attrs attribute.RawSet, typ uint8) {
	a, ok := attrs.First(typ)
	if !ok {
		_, _ = h.Write([]byte{typ, 0})
		return
	}
	_, _ = h.Write([]byte{typ, byte(len(a.Value))})
	_, _ = h.Write(a.Value)
}

func nasIdentity(attrs attribute.RawSet) string {
	if a, ok := attrs.First(attribute.TypeNASIPAddress); ok && len(a.Value) == 4 {
		return "ip4:" + net.IP(a.Value).String()
	}
	if a, ok := attrs.First(attribute.TypeNASIPv6Address); ok && len(a.Value) == 16 {
		return "ip6:" + net.IP(a.Value).String()
	}
	if a, ok := attrs.First(attribute.TypeNASIdentifier); ok && len(a.Value) > 0 {
		return "id:" + string(a.Value)
	}
	return ""
}

func textAttr(attrs attribute.RawSet, typ uint8) string {
	a, ok := attrs.First(typ)
	if !ok || len(a.Value) == 0 {
		return ""
	}
	return string(a.Value)
}

func uint32Val(a attribute.Raw) (uint32, bool) {
	if len(a.Value) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Value), true
}

func foldedOctets(attrs attribute.RawSet, lo, hi uint8) uint64 {
	var n uint64
	if a, ok := attrs.First(lo); ok {
		if v, ok := uint32Val(a); ok {
			n = uint64(v)
		}
	}
	if a, ok := attrs.First(hi); ok {
		if v, ok := uint32Val(a); ok {
			n += uint64(v) << 32
		}
	}
	return n
}

func durationAttr(attrs attribute.RawSet, typ uint8) time.Duration {
	a, ok := attrs.First(typ)
	if !ok {
		return 0
	}
	v, ok := uint32Val(a)
	if !ok {
		return 0
	}
	return time.Duration(v) * time.Second
}

func timeAttr(attrs attribute.RawSet, typ uint8) (time.Time, bool) {
	a, ok := attrs.First(typ)
	if !ok {
		return time.Time{}, false
	}
	v, ok := uint32Val(a)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0).UTC(), true
}

// RFC 2866 §5.10 Acct-Terminate-Cause.
var terminateCauseByNum = map[uint32]string{
	1:  "User-Request",
	2:  "Lost-Carrier",
	3:  "Lost-Service",
	4:  "Idle-Timeout",
	5:  "Session-Timeout",
	6:  "Admin-Reset",
	7:  "Admin-Reboot",
	8:  "Port-Error",
	9:  "NAS-Error",
	10: "NAS-Request",
	11: "NAS-Reboot",
	12: "Port-Unneeded",
	13: "Port-Preempted",
	14: "Port-Suspended",
	15: "Service-Unavailable",
	16: "Callback",
	17: "User-Error",
	18: "Host-Request",
}

func terminateCauseName(attrs attribute.RawSet) string {
	a, ok := attrs.First(attribute.TypeAcctTerminateCause)
	if !ok {
		return ""
	}
	v, ok := uint32Val(a)
	if !ok {
		return ""
	}
	return terminateCauseByNum[v]
}

func summarizeAttrs(attrs attribute.RawSet) []aaa.SafeAttributeSummary {
	if attrs.Len() == 0 {
		return nil
	}
	dict := attribute.Builtin()
	order := make([]string, 0, attrs.Len())
	counts := make(map[string]int, attrs.Len())
	for _, raw := range attrs {
		sum := dict.Summarize(raw)
		name := sum.Name
		if name == "" {
			name = "Type-" + strconv.Itoa(int(raw.Type))
		}
		if _, ok := counts[name]; !ok {
			order = append(order, name)
		}
		counts[name]++
	}
	out := make([]aaa.SafeAttributeSummary, 0, len(order))
	for _, name := range order {
		out = append(out, aaa.SafeAttributeSummary{Name: name, Count: counts[name]})
	}
	return out
}

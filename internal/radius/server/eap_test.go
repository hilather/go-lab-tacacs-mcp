package server

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

func eapIdentityAttr(id byte, ident string) attribute.Raw {
	pkt := encodeEAP(eapPacket{Code: eapCodeResponse, Identifier: id, Type: eapTypeIdentity, HasType: true, Data: []byte(ident)})
	return attribute.Raw{Type: attribute.TypeEAPMessage, Value: pkt}
}

func eapTypeAttr(id, typ byte, data []byte) attribute.Raw {
	pkt := encodeEAP(eapPacket{Code: eapCodeResponse, Identifier: id, Type: typ, HasType: true, Data: data})
	return attribute.Raw{Type: attribute.TypeEAPMessage, Value: pkt}
}

func eapMD5Attr(id byte, hash []byte) attribute.Raw {
	data := make([]byte, 1+len(hash))
	data[0] = byte(len(hash))
	copy(data[1:], hash)
	pkt := encodeEAP(eapPacket{Code: eapCodeResponse, Identifier: id, Type: eapTypeMD5, HasType: true, Data: data})
	return attribute.Raw{Type: attribute.TypeEAPMessage, Value: pkt}
}

func eapReq(t *testing.T, ra [16]byte, attrs attribute.RawSet, methods []string, store *runtime.ChallengeStore, ent []byte) (Request, Access) {
	t.Helper()
	in := signedAccessReq(t, ra, attrs, true)
	in.AllowedMethods = methods
	in.ClientID = "lab-switches"
	in.EndpointID = "radius-udp"
	in.Peer = netip.MustParseAddrPort("192.0.2.10:1812")
	in.Carrier = domain.CarrierRADIUSUDP
	h := Access{
		Store:   store,
		Entropy: bytes.NewReader(ent),
		AAA:     &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessAccept, ReasonCode: aaa.AccessReasonOK}},
	}
	return in, h
}

func firstEAP(t *testing.T, wire []byte) eapPacket {
	t.Helper()
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, reason := concatEAPMessage(pkt.Attributes)
	if reason != "" {
		t.Fatal(reason)
	}
	got, reason := parseEAP(raw)
	if reason != "" {
		t.Fatal(reason)
	}
	return got
}

func firstState(t *testing.T, wire []byte) []byte {
	t.Helper()
	pkt, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := pkt.Attributes.First(attribute.TypeState)
	if !ok {
		t.Fatal("missing State")
	}
	return append([]byte(nil), st.Value...)
}

func TestEAPIdentityIssuesMD5Challenge(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time {
		return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	})
	var ra [16]byte
	ra[0] = 0x81
	ent := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodPAP, methodCHAP, methodEAP}, store, ent)
	res := h.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonChallenge || res.Response[0] != byte(codec.CodeAccessChallenge) {
		t.Fatalf("got %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessChallenge, 1, ra, testSecret)
	eap := firstEAP(t, res.Response)
	if eap.Code != eapCodeRequest || eap.Type != eapTypeMD5 {
		t.Fatalf("eap=%+v", eap)
	}
	if store.Len() != 1 {
		t.Fatalf("store=%d", store.Len())
	}
	if _, ok := codec.Decode(res.Response); ok != nil {
		t.Fatal(ok)
	}
}

func TestEAPMD5SuccessAccepts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time { return now })
	var ra [16]byte
	ra[0] = 0x82
	ent := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodEAP}, store, ent)
	chal := h.Handle(context.Background(), in)
	if chal.Reason != ReasonChallenge {
		t.Fatalf("issue=%+v", chal)
	}
	state := firstState(t, chal.Response)
	eap := firstEAP(t, chal.Response)
	hash := credentials.CHAPResponse(eap.Identifier, []byte("unused"), bytes.Repeat([]byte{0x22}, 16))
	cont := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeState, Value: state},
		eapMD5Attr(eap.Identifier, hash),
	}, true)
	cont.AllowedMethods = []string{methodEAP}
	cont.ClientID = "lab-switches"
	cont.EndpointID = "radius-udp"
	cont.Peer = in.Peer
	cont.Carrier = domain.CarrierRADIUSUDP
	res := h.Handle(context.Background(), cont)
	if res.Action != ActionReply || res.Reason != ReasonOK || res.Response[0] != byte(codec.CodeAccessAccept) {
		t.Fatalf("accept=%+v", res)
	}
	got := firstEAP(t, res.Response)
	if got.Code != eapCodeSuccess {
		t.Fatalf("eap=%+v", got)
	}
	if store.Len() != 0 {
		t.Fatalf("store should be consumed: %d", store.Len())
	}
}

func TestEAPUnsupportedTypeRejectsWithoutState(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x83
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapTypeAttr(1, 25, []byte{0x00}), // PEAP
	}, []string{methodEAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonUnsupportedEAPMethod || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("got %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
	pkt, err := codec.Decode(res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkt.Attributes.First(attribute.TypeState); ok {
		t.Fatal("must not leak State")
	}
	eap := firstEAP(t, res.Response)
	if eap.Code != eapCodeFailure || eap.HasType {
		t.Fatalf("generic failure=%+v", eap)
	}
	if store.Len() != 0 {
		t.Fatalf("must not store State: %d", store.Len())
	}
}

func TestEAPTooLongRejects(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x84
	attrs := attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("lab-admin")}}
	// 5 × 253 > 1020
	for i := 0; i < 5; i++ {
		attrs = append(attrs, attribute.Raw{Type: attribute.TypeEAPMessage, Value: bytes.Repeat([]byte{0x02}, 253)})
	}
	in, h := eapReq(t, ra, attrs, []string{methodEAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonEAPTooLong || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("got %+v", res)
	}
	eap := firstEAP(t, res.Response)
	if eap.Code != eapCodeFailure {
		t.Fatalf("eap=%+v", eap)
	}
}

func TestEAPNotAllowedNoChallenge(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x85
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodPAP, methodCHAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonUnsupportedMethod || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("got %+v", res)
	}
	pkt, err := codec.Decode(res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attributes.AllOf(attribute.TypeEAPMessage).Len() != 0 {
		t.Fatal("opt-out EAP must not emit EAP-Failure")
	}
	if _, ok := pkt.Attributes.First(attribute.TypeState); ok {
		t.Fatal("must not Challenge")
	}
	if store.Len() != 0 {
		t.Fatal("must not store")
	}
}

func TestEAPConflictingPAP(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x86
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodPAP, methodCHAP, methodEAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonConflictingAuth {
		t.Fatalf("got %+v", res)
	}
}

func TestEAPNAKFailure(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x87
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapTypeAttr(1, eapTypeNAK, []byte{eapTypeMD5}),
	}, []string{methodEAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonUnsupportedEAPMethod {
		t.Fatalf("got %+v", res)
	}
	eap := firstEAP(t, res.Response)
	if eap.Code != eapCodeFailure || eap.HasType {
		t.Fatalf("eap=%+v", eap)
	}
}

func TestEAPEmptyIdentityAsksIdentity(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x88
	in, h := eapReq(t, ra, attribute.RawSet{
		eapIdentityAttr(1, ""),
	}, []string{methodEAP}, store, bytes.Repeat([]byte{0x33}, 16))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonChallenge || res.Response[0] != byte(codec.CodeAccessChallenge) {
		t.Fatalf("got %+v", res)
	}
	eap := firstEAP(t, res.Response)
	if eap.Code != eapCodeRequest || eap.Type != eapTypeIdentity {
		t.Fatalf("eap=%+v", eap)
	}
}

func TestEAPIdentityUserNameMismatch(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0x89
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "other-user"),
	}, []string{methodEAP}, store, bytes.Repeat([]byte{1}, 32))
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonConflictingAuth {
		t.Fatalf("got %+v", res)
	}
}

func TestEAPMustChangeIndistinguishableFromBadPassword(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time { return now })
	var ra [16]byte
	ra[0] = 0x8a

	badAuth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonBadCredentials}}
	mustAuth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPasswordChangeRequired}}

	issue := func(h Access) (state []byte, id byte) {
		ent := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
		h.Entropy = bytes.NewReader(ent)
		h.Store = store
		in := signedAccessReq(t, ra, attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			eapIdentityAttr(1, "lab-admin"),
		}, true)
		in.AllowedMethods = []string{methodEAP}
		in.ClientID = "lab-switches"
		in.EndpointID = "radius-udp"
		in.Peer = netip.MustParseAddrPort("192.0.2.10:1812")
		in.Carrier = domain.CarrierRADIUSUDP
		res := h.Handle(context.Background(), in)
		if res.Reason != ReasonChallenge {
			t.Fatalf("issue=%+v", res)
		}
		return firstState(t, res.Response), firstEAP(t, res.Response).Identifier
	}

	continueMD5 := func(h Access, state []byte, id byte) Result {
		hash := credentials.CHAPResponse(id, []byte("x"), bytes.Repeat([]byte{0x22}, 16))
		in := signedAccessReq(t, ra, attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeState, Value: state},
			eapMD5Attr(id, hash),
		}, true)
		in.AllowedMethods = []string{methodEAP}
		in.ClientID = "lab-switches"
		in.EndpointID = "radius-udp"
		in.Peer = netip.MustParseAddrPort("192.0.2.10:1812")
		in.Carrier = domain.CarrierRADIUSUDP
		return h.Handle(context.Background(), in)
	}

	st1, id1 := issue(Access{AAA: badAuth})
	bad := continueMD5(Access{AAA: badAuth, Store: store}, st1, id1)
	st2, id2 := issue(Access{AAA: mustAuth})
	must := continueMD5(Access{AAA: mustAuth, Store: store}, st2, id2)

	if bad.Response[0] != byte(codec.CodeAccessReject) || must.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("codes bad=%d must=%d", bad.Response[0], must.Response[0])
	}
	if bad.Reason != ReasonBadCredentials || must.Reason != ReasonPasswordChangeRequired {
		t.Fatalf("reasons bad=%s must=%s", bad.Reason, must.Reason)
	}
	badEAP := firstEAP(t, bad.Response)
	mustEAP := firstEAP(t, must.Response)
	if badEAP.Code != eapCodeFailure || mustEAP.Code != eapCodeFailure {
		t.Fatalf("eap codes %d %d", badEAP.Code, mustEAP.Code)
	}
	if badEAP.HasType || mustEAP.HasType || len(badEAP.Data) != 0 || len(mustEAP.Data) != 0 {
		t.Fatalf("payload distinguish bad=%+v must=%+v", badEAP, mustEAP)
	}
	badPkt, _ := codec.Decode(bad.Response)
	mustPkt, _ := codec.Decode(must.Response)
	if _, ok := badPkt.Attributes.First(attribute.TypeState); ok {
		t.Fatal("bad-password must not carry State")
	}
	if _, ok := mustPkt.Attributes.First(attribute.TypeState); ok {
		t.Fatal("must_change must not carry State")
	}
}

func TestEAPGenericFailureBytes(t *testing.T) {
	t.Parallel()
	a := genericEAPFailure(7)
	b := genericEAPFailure(9)
	if a[0] != eapCodeFailure || b[0] != eapCodeFailure || len(a) != 4 || len(b) != 4 {
		t.Fatalf("%x %x", a, b)
	}
	if a[2] != 0 || a[3] != 4 {
		t.Fatalf("length %x", a)
	}
}

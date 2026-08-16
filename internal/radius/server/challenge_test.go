package server

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

func accessWithState(t *testing.T, ra [16]byte, state []byte, peer netip.AddrPort) Request {
	t.Helper()
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeState, Value: state},
	}, true)
	in.ClientID = "lab-switches"
	in.EndpointID = "radius-udp"
	in.Peer = peer
	in.Carrier = domain.CarrierRADIUSUDP
	return in
}

func TestAccessUnknownStateRejects(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x61
	peer := netip.MustParseAddrPort("192.0.2.10:1812")
	in := accessWithState(t, ra, []byte("forged-client-state"), peer)
	res := Access{}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonInvalidState {
		t.Fatalf("nil store: %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
	if res.Response[0] == byte(codec.CodeAccessChallenge) {
		t.Fatal("must not emit Access-Challenge")
	}

	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time {
		return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	})
	res = Access{Store: store}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonInvalidState {
		t.Fatalf("unknown state: %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
}

func TestAccessExpiredAndBindingStateRejects(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	clock := now
	store := runtime.NewChallengeStore(16, 64<<10, 5*time.Second, func() time.Time { return clock })
	peer := netip.MustParseAddrPort("192.0.2.10:4242")
	state := []byte("issued-state-16b")
	issue := runtime.ChallengeIssue{
		State:      state,
		EndpointID: "radius-udp",
		ClientID:   "lab-switches",
		Bind:       runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: peer.Addr()},
		Method:     "eap",
		Step:       runtime.StepMD5Challenge,
	}
	if reason := IssueChallenge(store, Request{EndpointID: "radius-udp", ClientID: "lab-switches"}, issue); reason != "" {
		t.Fatal(reason)
	}

	var ra [16]byte
	ra[0] = 0x62
	wrongPeer := accessWithState(t, ra, state, netip.MustParseAddrPort("198.51.100.9:9"))
	res := Access{Store: store}.Handle(context.Background(), wrongPeer)
	if res.Reason != ReasonChallengeBinding || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("binding: %+v", res)
	}

	clock = clock.Add(6 * time.Second)
	expired := accessWithState(t, ra, state, peer)
	res = Access{Store: store}.Handle(context.Background(), expired)
	if res.Reason != ReasonChallengeExpired {
		t.Fatalf("expired: %+v", res)
	}
}

func TestAccessChallengeCapacityReason(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(1, 64<<10, 30*time.Second, func() time.Time { return now })
	peer := netip.MustParseAddr("192.0.2.10")
	in := Request{EndpointID: "ep", ClientID: "c", Carrier: domain.CarrierRADIUSUDP, Peer: netip.AddrPortFrom(peer, 1)}
	first := runtime.ChallengeIssue{
		State:      []byte("first-state-16b!!"),
		Bind:       runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: peer},
		Method:     "eap",
		Step:       runtime.StepIdentity,
		EndpointID: "ep",
		ClientID:   "c",
	}
	if reason := IssueChallenge(store, in, first); reason != "" {
		t.Fatal(reason)
	}
	second := first
	second.State = []byte("second-state-16b!")
	if reason := IssueChallenge(store, in, second); reason != ReasonChallengeCapacity {
		t.Fatalf("capacity=%q", reason)
	}
	if wireAccessReason(ReasonChallengeCapacity) != ReasonChallengeCapacity {
		t.Fatal("capacity must not collapse to bad credentials")
	}
}

func TestAccessInjectedProviderConsumeNoChallenge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time { return now })
	peer := netip.MustParseAddrPort("192.0.2.10:1812")
	state := []byte("provider-state-16")
	if store.Issue(runtime.ChallengeIssue{
		State:      state,
		EndpointID: "radius-udp",
		ClientID:   "lab-switches",
		Bind:       runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: peer.Addr()},
		Method:     "eap",
		Step:       runtime.StepMD5Challenge,
	}) != runtime.IssueOK {
		t.Fatal("issue")
	}
	var ra [16]byte
	ra[0] = 0x63
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessAccept, ReasonCode: aaa.AccessReasonOK}}
	res := Access{AAA: auth, Store: store}.Handle(context.Background(), accessWithState(t, ra, state, peer))
	if res.Action != ActionReply || res.Reason != ReasonUnsupportedMethod {
		t.Fatalf("consumed continuation without EAP provider: %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
	if res.Response[0] == byte(codec.CodeAccessChallenge) {
		t.Fatal("must not emit Access-Challenge")
	}
	if auth.got.UserID != "" {
		t.Fatal("PAP/CHAP authenticator must not run on a continuation")
	}
}

func TestAccessTLSBindFromInjectedCert(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time { return now })
	var fp [32]byte
	fp[0] = 0x44
	state := []byte("tls-state-16bytes")
	if store.Issue(runtime.ChallengeIssue{
		State:      state,
		EndpointID: "radius-tls",
		ClientID:   "lab-radsec",
		Bind:       runtime.ChallengeBind{Kind: runtime.BindTLSCert, CertFP: fp},
		Method:     "eap",
		Step:       runtime.StepIdentity,
	}) != runtime.IssueOK {
		t.Fatal("issue")
	}
	var ra [16]byte
	ra[0] = 0x64
	in := accessWithState(t, ra, state, netip.MustParseAddrPort("203.0.113.5:2083"))
	in.Carrier = domain.CarrierRADIUSTLS
	in.EndpointID = "radius-tls"
	in.ClientID = "lab-radsec"
	in.TLSCertFP = fp
	bad := in
	bad.TLSCertFP[0] = 0x99
	res := Access{Store: store}.Handle(context.Background(), bad)
	if res.Reason != ReasonChallengeBinding {
		t.Fatalf("tls mismatch: %+v", res)
	}
	res = Access{Store: store}.Handle(context.Background(), in)
	if res.Reason != ReasonUnsupportedMethod {
		t.Fatalf("tls consume: %+v", res)
	}
}

func TestAccessChallengeOutcomeNotAdvertised(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x65
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{
		Outcome:    aaa.RadiusAccessChallenge,
		ReasonCode: aaa.AccessReasonChallenge,
		Challenge:  &aaa.RadiusChallenge{State: []byte("must-not-wire")},
	}}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
	}, true)
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("challenge outcome must reject: %+v", res)
	}
	if res.Reason != ReasonInternal {
		t.Fatalf("reason=%s", res.Reason)
	}
}

func TestAccessPAPUnchangedWithStore(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x66
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessAccept, ReasonCode: aaa.AccessReasonOK}}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
	}, true)
	in.Carrier = domain.CarrierRADIUSUDP
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	res := Access{AAA: auth, Store: store}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonOK || res.Response[0] != byte(codec.CodeAccessAccept) {
		t.Fatalf("PAP with unused store: %+v", res)
	}
	if auth.got.Context.Carrier != domain.CarrierRADIUSUDP {
		t.Fatalf("carrier=%s", auth.got.Context.Carrier)
	}
}

func TestWireAccessReasonChallengeCodes(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		ReasonInvalidState, ReasonChallengeExpired, ReasonChallengeBinding,
		ReasonChallengeCapacity, ReasonChallenge,
	} {
		if got := wireAccessReason(code); got != code {
			t.Errorf("%s collapsed to %s", code, got)
		}
	}
	if got := wireAccessReason("not-a-reason"); got != ReasonBadCredentials {
		t.Fatalf("unknown=%s", got)
	}
}

func TestAccessConcurrentStateConsume(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, func() time.Time { return now })
	peer := netip.MustParseAddrPort("192.0.2.10:1812")
	state := []byte("race-handle-state")
	if store.Issue(runtime.ChallengeIssue{
		State:      state,
		EndpointID: "radius-udp",
		ClientID:   "lab-switches",
		Bind:       runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: peer.Addr()},
		Method:     "eap",
		Step:       runtime.StepMD5Challenge,
	}) != runtime.IssueOK {
		t.Fatal("issue")
	}
	const n = 16
	var unsupported, invalid atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			var ra [16]byte
			ra[0] = 0x70
			res := Access{Store: store}.Handle(context.Background(), accessWithState(t, ra, state, peer))
			switch res.Reason {
			case ReasonUnsupportedMethod:
				unsupported.Add(1)
			case ReasonInvalidState:
				invalid.Add(1)
			default:
				t.Errorf("reason=%s", res.Reason)
			}
		}()
	}
	wg.Wait()
	if unsupported.Load() != 1 || invalid.Load() != n-1 {
		t.Fatalf("winner=%d invalid=%d", unsupported.Load(), invalid.Load())
	}
}

func TestIssueChallengeDefaultsBindFromRequest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	store := runtime.NewChallengeStore(8, 64<<10, 30*time.Second, func() time.Time { return now })
	peer := netip.MustParseAddrPort("192.0.2.10:1812")
	state := []byte("auto-bind-state16")
	in := Request{
		EndpointID: "ep",
		ClientID:   "c",
		Carrier:    domain.CarrierRADIUSUDP,
		Peer:       peer,
	}
	if reason := IssueChallenge(store, in, runtime.ChallengeIssue{State: state, Method: "eap", Step: runtime.StepIdentity}); reason != "" {
		t.Fatal(reason)
	}
	bind := runtime.ChallengeBind{Kind: runtime.BindUDPIP, SourceIP: peer.Addr()}
	if _, res := store.Consume("ep", state, "c", bind); res != runtime.ConsumeOK {
		t.Fatalf("auto bind consume=%v", res)
	}

	if reason := IssueChallenge(store, Request{EndpointID: "ep", ClientID: "c"}, runtime.ChallengeIssue{State: []byte("no-peer-state-16")}); reason != ReasonChallengeBinding {
		t.Fatalf("missing peer bind=%q", reason)
	}

	var fp [32]byte
	fp[0] = 0x7e
	tlsState := []byte("auto-tls-state-16")
	tlsIn := Request{
		EndpointID: "ep-tls",
		ClientID:   "c-tls",
		Carrier:    domain.CarrierRADIUSTLS,
		TLSCertFP:  fp,
	}
	if reason := IssueChallenge(store, tlsIn, runtime.ChallengeIssue{State: tlsState, Method: "eap", Step: runtime.StepIdentity}); reason != "" {
		t.Fatal(reason)
	}
	if _, res := store.Consume("ep-tls", tlsState, "c-tls", runtime.ChallengeBind{Kind: runtime.BindTLSCert, CertFP: fp}); res != runtime.ConsumeOK {
		t.Fatalf("auto tls bind consume=%v", res)
	}
}

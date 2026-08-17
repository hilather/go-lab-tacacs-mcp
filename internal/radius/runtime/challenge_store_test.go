package runtime

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func udpBind(ip string) ChallengeBind {
	return ChallengeBind{Kind: BindUDPIP, SourceIP: netip.MustParseAddr(ip)}
}

func tlsBind(b byte) ChallengeBind {
	var fp [32]byte
	fp[0] = b
	return ChallengeBind{Kind: BindTLSCert, CertFP: fp}
}

func issueRec(state, endpoint, client string, bind ChallengeBind) ChallengeIssue {
	return ChallengeIssue{
		State:      []byte(state),
		EndpointID: endpoint,
		ClientID:   client,
		Bind:       bind,
		UserID:     "lab-admin",
		Method:     "eap",
		EAPID:      1,
		EAPType:    4,
		Step:       StepMD5Challenge,
		Revision:   7,
	}
}

func TestChallengeIssueConsumeUDPAndTLS(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(16, 64<<10, 30*time.Second, testNow(now))

	udp := udpBind("192.0.2.10")
	if got := s.Issue(issueRec("state-udp-16b!!", "ep-udp", "lab-switches", udp)); got != IssueOK {
		t.Fatalf("udp issue=%v", got)
	}
	rec, res := s.Consume("ep-udp", []byte("state-udp-16b!!"), "lab-switches", udp)
	if res != ConsumeOK || rec.UserID != "lab-admin" || rec.Step != StepMD5Challenge || rec.Revision != 7 {
		t.Fatalf("udp consume=%v rec=%+v", res, rec)
	}
	if rec.Bind.Kind != BindUDPIP || rec.Bind.SourceIP != udp.SourceIP {
		t.Fatalf("udp bind=%+v", rec.Bind)
	}
	if _, res = s.Consume("ep-udp", []byte("state-udp-16b!!"), "lab-switches", udp); res != ConsumeUnknown {
		t.Fatalf("replay after consume=%v", res)
	}

	tls := tlsBind(0xab)
	if got := s.Issue(issueRec("state-tls-16b!!", "ep-tls", "lab-radsec", tls)); got != IssueOK {
		t.Fatalf("tls issue=%v", got)
	}
	// TLS peer IP is not part of the bind.
	rec, res = s.Consume("ep-tls", []byte("state-tls-16b!!"), "lab-radsec", tls)
	if res != ConsumeOK || rec.Bind.Kind != BindTLSCert || rec.Bind.CertFP != tls.CertFP {
		t.Fatalf("tls consume=%v rec=%+v", res, rec)
	}
}

func TestChallengeUnknownExpiredBindingCapacity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	clock := now
	s := NewChallengeStore(1, 64<<10, 5*time.Second, func() time.Time { return clock })
	bind := udpBind("198.51.100.2")

	if _, res := s.Consume("ep", []byte("forged-client-state"), "c", bind); res != ConsumeUnknown {
		t.Fatalf("unknown=%v", res)
	}
	if got := s.Issue(issueRec("live-state-16b!!", "ep", "c", bind)); got != IssueOK {
		t.Fatal(got)
	}
	if _, res := s.Consume("ep", []byte("live-state-16b!!"), "c", udpBind("203.0.113.9")); res != ConsumeBinding {
		t.Fatalf("source ip mismatch=%v", res)
	}
	if _, res := s.Consume("ep", []byte("live-state-16b!!"), "other-client", bind); res != ConsumeBinding {
		t.Fatalf("client mismatch=%v", res)
	}
	if s.Len() != 1 {
		t.Fatalf("binding miss must not consume: len=%d", s.Len())
	}

	other := udpBind("192.0.2.99")
	if got := s.Issue(issueRec("second-state-16b", "ep-2", "c2", other)); got != IssueSaturated {
		t.Fatalf("entry cap=%v", got)
	}
	if s.Saturations() != 1 {
		t.Fatalf("saturations=%d", s.Saturations())
	}

	var hooks int
	capped := NewChallengeStoreWithHook(1, 64<<10, 30*time.Second, testNow(now), func() { hooks++ })
	if capped.Issue(issueRec("hook-state-16b!!!", "ep", "c", bind)) != IssueOK {
		t.Fatal("hook first")
	}
	if capped.Issue(issueRec("hook-state-2-16b!!", "ep-2", "c2", other)) != IssueSaturated || hooks != 1 {
		t.Fatalf("hook saturations=%d hooks=%d", capped.Saturations(), hooks)
	}

	clock = clock.Add(6 * time.Second)
	if _, res := s.Consume("ep", []byte("live-state-16b!!"), "c", bind); res != ConsumeExpired {
		t.Fatalf("expired=%v", res)
	}
	if s.Len() != 0 {
		t.Fatalf("expired record must be deleted: len=%d", s.Len())
	}
}

func TestChallengeByteCapacityAndReset(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	// Tiny byte cap admits the first record then fail-closes.
	s := NewChallengeStore(64, 200, 30*time.Second, testNow(now))
	bind := udpBind("192.0.2.1")
	if got := s.Issue(issueRec("aaaaaaaaaaaaaaaa", "endpoint-id", "client-id", bind)); got != IssueOK {
		t.Fatalf("first=%v", got)
	}
	if got := s.Issue(issueRec("bbbbbbbbbbbbbbbb", "endpoint-id", "client-id", bind)); got != IssueSaturated {
		t.Fatalf("bytes cap=%v", got)
	}
	s.Reset()
	if s.Len() != 0 {
		t.Fatalf("reset len=%d", s.Len())
	}
	if got := s.Issue(issueRec("cccccccccccccccc", "endpoint-id", "client-id", bind)); got != IssueOK {
		t.Fatalf("after reset=%v", got)
	}
}

func TestChallengeDoesNotOverwriteOrCreateFromClientState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(8, 64<<10, 30*time.Second, testNow(now))
	bind := udpBind("192.0.2.8")
	first := issueRec("same-state-bytes!", "ep", "c", bind)
	first.UserID = "one"
	if got := s.Issue(first); got != IssueOK {
		t.Fatal(got)
	}
	second := first
	second.UserID = "two"
	if got := s.Issue(second); got != IssueExists {
		t.Fatalf("overwrite=%v", got)
	}
	rec, res := s.Consume("ep", []byte("same-state-bytes!"), "c", bind)
	if res != ConsumeOK || rec.UserID != "one" {
		t.Fatalf("kept first writer: %+v %v", rec, res)
	}
	if s.Issue(ChallengeIssue{State: []byte("x"), EndpointID: "", ClientID: "c", Bind: bind}) != IssueInvalid {
		t.Fatal("empty endpoint must be invalid")
	}
}

func TestChallengeTLSBindMismatchAndUDPPortIgnored(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(8, 64<<10, 30*time.Second, testNow(now))
	a := tlsBind(1)
	b := tlsBind(2)
	if s.Issue(issueRec("tls-state-16bytes", "ep", "c", a)) != IssueOK {
		t.Fatal("issue")
	}
	if _, res := s.Consume("ep", []byte("tls-state-16bytes"), "c", b); res != ConsumeBinding {
		t.Fatalf("cert mismatch=%v", res)
	}
	if _, res := s.Consume("ep", []byte("tls-state-16bytes"), "c", udpBind("192.0.2.1")); res != ConsumeBinding {
		t.Fatalf("kind mismatch=%v", res)
	}
	if _, res := s.Consume("ep", []byte("tls-state-16bytes"), "c", a); res != ConsumeOK {
		t.Fatalf("matching cert=%v", res)
	}
}

func TestChallengeRecordStringOmitsSecrets(t *testing.T) {
	t.Parallel()
	rec := ChallengeRecord{
		EndpointID:   "ep",
		ClientID:     "c",
		Bind:         tlsBind(9),
		UserID:       "lab-admin",
		MD5Challenge: []byte("md5-challenge-secret"),
		Step:         StepMD5Challenge,
	}
	issue := ChallengeIssue{
		State:        []byte("raw-state-secret!!"),
		EndpointID:   "ep",
		ClientID:     "c",
		Bind:         tlsBind(9),
		MD5Challenge: []byte("md5-challenge-secret"),
		Step:         StepMD5Challenge,
	}
	for _, got := range []string{rec.String(), rec.GoString(), fmt.Sprintf("%v", rec), fmt.Sprintf("%+v", rec), fmt.Sprintf("%#v", rec),
		issue.String(), issue.GoString(), fmt.Sprintf("%v", issue), fmt.Sprintf("%+v", issue), fmt.Sprintf("%#v", issue)} {
		if strings.Contains(got, "md5-challenge-secret") || strings.Contains(got, "raw-state-secret") || strings.Contains(got, string(rec.Bind.CertFP[:])) {
			t.Fatalf("leaked secret material: %s", got)
		}
	}
}

func TestChallengeConsumeCopiesMD5AndReplayUnknown(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(8, 64<<10, 30*time.Second, testNow(now))
	bind := udpBind("192.0.2.10")
	md5 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	in := issueRec("md5-state-16bytes", "ep", "c", bind)
	in.MD5Challenge = append([]byte(nil), md5...)
	if s.Issue(in) != IssueOK {
		t.Fatal("issue")
	}
	rec, res := s.Consume("ep", []byte("md5-state-16bytes"), "c", bind)
	if res != ConsumeOK {
		t.Fatalf("consume=%v", res)
	}
	if !bytes.Equal(rec.MD5Challenge, md5) {
		t.Fatalf("copy=%x want %x", rec.MD5Challenge, md5)
	}
	if _, res = s.Consume("ep", []byte("md5-state-16bytes"), "c", bind); res != ConsumeUnknown {
		t.Fatalf("second consume=%v", res)
	}
}

func TestChallengeConcurrentConsumeOneWinner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(8, 64<<10, 30*time.Second, testNow(now))
	bind := udpBind("192.0.2.50")
	if s.Issue(issueRec("race-state-16b!!", "ep", "c", bind)) != IssueOK {
		t.Fatal("issue")
	}
	const n = 32
	var ok, unknown atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, res := s.Consume("ep", []byte("race-state-16b!!"), "c", bind)
			switch res {
			case ConsumeOK:
				ok.Add(1)
			case ConsumeUnknown:
				unknown.Add(1)
			default:
				t.Errorf("unexpected %v", res)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("winners=%d unknown=%d", ok.Load(), unknown.Load())
	}
	if unknown.Load() != n-1 {
		t.Fatalf("unknown=%d want %d", unknown.Load(), n-1)
	}
}

func BenchmarkRadiusChallengeLookup(b *testing.B) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	s := NewChallengeStore(4096, 1<<20, 30*time.Second, testNow(now))
	bind := udpBind("192.0.2.7")
	state := []byte("bench-state-16b!")
	in := issueRec(string(state), "ep", "c", bind)
	if s.Issue(in) != IssueOK {
		b.Fatal("issue")
	}
	// Re-issue after each consume so the lookup path stays hot.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, res := s.Consume("ep", state, "c", bind)
		if res != ConsumeOK {
			b.Fatalf("consume=%v", res)
		}
		if s.Issue(in) != IssueOK {
			b.Fatal("reissue")
		}
	}
}

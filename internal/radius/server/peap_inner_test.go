package server

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"sync"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/eap/peap"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
)

func TestEAPPEAPInnerMSCHAPAccept(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0xa1
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodPEAP}, store, nil)
	peer := newPEAPTestPeer(t)
	state, eapID := peapIdentityStart(t, h, in)
	res := peapPumpHandshake(t, h, in, ra, peer, state, eapID)
	if res.Reason != ReasonChallenge {
		t.Fatalf("after handshake %+v", res)
	}
	inner, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, err := peap.DecodeInner(inner)
	if err != nil || req.Type != peap.InnerIdentity {
		t.Fatalf("inner=%+v err=%v", req, err)
	}
	ident := peap.EncodeInner(peap.InnerPacket{
		Code: 2, Identifier: req.Identifier, Type: peap.InnerIdentity, HasType: true, Data: []byte("lab-admin"),
	})
	if err := peer.WriteApp(ident); err != nil {
		t.Fatal(err)
	}
	state = firstState(t, res.Response)
	eapID = firstEAP(t, res.Response).Identifier
	res = peapSendTLS(t, h, in, ra, state, eapID, peer.TakeTLS())
	if res.Reason != ReasonChallenge {
		t.Fatalf("after identity %+v", res)
	}
	feedServerTLS(t, peer, res)
	chalRaw, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	chalPkt, err := peap.DecodeInner(chalRaw)
	if err != nil || chalPkt.Type != peap.InnerMSCHAPv2 {
		t.Fatalf("mschap=%+v err=%v", chalPkt, err)
	}
	msResp := peapDummyMSCHAPResponse(chalPkt)
	if err := peer.WriteApp(msResp); err != nil {
		t.Fatal(err)
	}
	state = firstState(t, res.Response)
	eapID = firstEAP(t, res.Response).Identifier
	res = peapSendTLS(t, h, in, ra, state, eapID, peer.TakeTLS())
	if res.Reason != ReasonChallenge {
		t.Fatalf("after mschap %+v", res)
	}
	feedServerTLS(t, peer, res)
	state = firstState(t, res.Response)
	eapID = firstEAP(t, res.Response).Identifier
	res = peapSendTLS(t, h, in, ra, state, eapID, nil)
	if res.Reason != ReasonOK || res.Response[0] != byte(codec.CodeAccessAccept) {
		t.Fatalf("accept=%+v", res)
	}
	got := firstEAP(t, res.Response)
	if got.Code != eapCodeSuccess {
		t.Fatalf("outer eap=%+v", got)
	}
}

func TestEAPPEAPInnerMSCHAPReject(t *testing.T) {
	t.Parallel()
	store := runtime.NewChallengeStore(16, 64<<10, 30*time.Second, time.Now)
	var ra [16]byte
	ra[0] = 0xa2
	in, h := eapReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		eapIdentityAttr(1, "lab-admin"),
	}, []string{methodPEAP}, store, nil)
	h.AAA = &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonBadCredentials}}
	peer := newPEAPTestPeer(t)
	state, eapID := peapIdentityStart(t, h, in)
	res := peapPumpHandshake(t, h, in, ra, peer, state, eapID)
	inner, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, err := peap.DecodeInner(inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteApp(peap.EncodeInner(peap.InnerPacket{
		Code: 2, Identifier: req.Identifier, Type: peap.InnerIdentity, HasType: true, Data: []byte("lab-admin"),
	})); err != nil {
		t.Fatal(err)
	}
	state = firstState(t, res.Response)
	eapID = firstEAP(t, res.Response).Identifier
	res = peapSendTLS(t, h, in, ra, state, eapID, peer.TakeTLS())
	feedServerTLS(t, peer, res)
	chalRaw, err := peer.ReadApp(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	chalPkt, err := peap.DecodeInner(chalRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteApp(peapDummyMSCHAPResponse(chalPkt)); err != nil {
		t.Fatal(err)
	}
	state = firstState(t, res.Response)
	eapID = firstEAP(t, res.Response).Identifier
	res = peapSendTLS(t, h, in, ra, state, eapID, peer.TakeTLS())
	if res.Reason != ReasonBadCredentials || res.Response[0] != byte(codec.CodeAccessReject) {
		t.Fatalf("reject=%+v", res)
	}
}

func peapIdentityStart(t *testing.T, h Access, in Request) ([]byte, byte) {
	t.Helper()
	res := h.Handle(context.Background(), in)
	if res.Reason != ReasonChallenge {
		t.Fatalf("start=%+v", res)
	}
	return firstState(t, res.Response), firstEAP(t, res.Response).Identifier
}

func peapPumpHandshake(t *testing.T, h Access, in Request, ra [16]byte, peer *peapTestPeer, state []byte, eapID byte) Result {
	t.Helper()
	hello := peer.WaitTLS(2 * time.Second)
	res := Result{}
	for _, part := range peap.EncodeFlight(hello) {
		res = peapSendBody(t, h, in, ra, state, eapID, part)
		if res.Reason != ReasonChallenge {
			t.Fatalf("hello frag %+v", res)
		}
		state, eapID = firstState(t, res.Response), firstEAP(t, res.Response).Identifier
		state, eapID, res = drainPEAPFragments(t, h, in, ra, peer, state, eapID, res)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !peer.HandshakeDone() {
		more := peer.TakeTLS()
		if len(more) == 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		for _, part := range peap.EncodeFlight(more) {
			res = peapSendBody(t, h, in, ra, state, eapID, part)
			if res.Reason != ReasonChallenge {
				t.Fatalf("hs %+v", res)
			}
			state, eapID = firstState(t, res.Response), firstEAP(t, res.Response).Identifier
			state, eapID, res = drainPEAPFragments(t, h, in, ra, peer, state, eapID, res)
		}
	}
	if !peer.HandshakeDone() {
		t.Fatal("peer handshake incomplete")
	}
	if more := peer.TakeTLS(); len(more) > 0 {
		for _, part := range peap.EncodeFlight(more) {
			res = peapSendBody(t, h, in, ra, state, eapID, part)
			if res.Reason != ReasonChallenge {
				t.Fatalf("finished %+v", res)
			}
			state, eapID = firstState(t, res.Response), firstEAP(t, res.Response).Identifier
			state, eapID, res = drainPEAPFragments(t, h, in, ra, peer, state, eapID, res)
		}
	}
	return res
}

func drainPEAPFragments(t *testing.T, h Access, in Request, ra [16]byte, peer *peapTestPeer, state []byte, eapID byte, res Result) ([]byte, byte, Result) {
	t.Helper()
	for i := 0; i < 8; i++ {
		eap := firstEAP(t, res.Response)
		body, err := peap.Parse(eap.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(body.TLSData) > 0 {
			peer.PushTLS(body.TLSData)
		}
		if !body.MoreFragments {
			return state, eapID, res
		}
		res = peapSendBody(t, h, in, ra, state, eapID, peap.Encode(peap.Payload{Version: peap.Version0}))
		if res.Reason != ReasonChallenge {
			t.Fatalf("ack frag %+v", res)
		}
		state, eapID = firstState(t, res.Response), firstEAP(t, res.Response).Identifier
	}
	t.Fatal("too many PEAP fragments")
	return state, eapID, res
}

func peapSendTLS(t *testing.T, h Access, in Request, ra [16]byte, state []byte, eapID byte, tlsData []byte) Result {
	t.Helper()
	parts := peap.EncodeFlight(tlsData)
	var res Result
	for i, part := range parts {
		res = peapSendBody(t, h, in, ra, state, eapID, part)
		if i < len(parts)-1 {
			if res.Reason != ReasonChallenge {
				t.Fatalf("frag %+v", res)
			}
			state = firstState(t, res.Response)
			eapID = firstEAP(t, res.Response).Identifier
		}
	}
	return res
}

func peapSendBody(t *testing.T, h Access, seed Request, ra [16]byte, state []byte, eapID byte, body []byte) Result {
	t.Helper()
	pkt := encodeEAP(eapPacket{Code: eapCodeResponse, Identifier: eapID, Type: eapTypePEAP, HasType: true, Data: body})
	attrs := attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeState, Value: state},
	}
	attrs = append(attrs, eapMessageAttrs(pkt)...)
	cont := signedAccessReq(t, ra, attrs, true)
	cont.AllowedMethods = []string{methodPEAP}
	cont.ClientID = seed.ClientID
	cont.EndpointID = seed.EndpointID
	cont.Peer = seed.Peer
	cont.Carrier = seed.Carrier
	return h.Handle(context.Background(), cont)
}

func feedServerTLS(t *testing.T, peer *peapTestPeer, res Result) {
	t.Helper()
	eap := firstEAP(t, res.Response)
	body, err := peap.Parse(eap.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(body.TLSData) > 0 {
		peer.PushTLS(body.TLSData)
	}
}

func peapDummyMSCHAPResponse(req peap.InnerPacket) []byte {
	resp := make([]byte, 49)
	data := append([]byte{peap.MSCHAPOpResponse, req.Data[1], 0, 54, 49}, resp...)
	data = append(data, []byte("lab-admin")...)
	return peap.EncodeInner(peap.InnerPacket{
		Code: 2, Identifier: req.Identifier, Type: peap.InnerMSCHAPv2, HasType: true, Data: data,
	})
}

type peapTestPeer struct {
	conn     *tls.Conn
	toPeer   *testPipe
	fromPeer *testPipe
	hs       chan error
	hsDone   bool
	hsErr    error
}

func newPEAPTestPeer(t *testing.T) *peapTestPeer {
	t.Helper()
	toPeer, fromPeer := &testPipe{}, &testPipe{}
	toPeer.cond = sync.NewCond(&toPeer.mu)
	fromPeer.cond = sync.NewCond(&fromPeer.mu)
	conn := tls.Client(&testDuplex{r: toPeer, w: fromPeer}, &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		ServerName:             "peap.lab.example",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	})
	hs := make(chan error, 1)
	go func() { hs <- conn.Handshake() }()
	return &peapTestPeer{conn: conn, toPeer: toPeer, fromPeer: fromPeer, hs: hs}
}

func (p *peapTestPeer) WaitTLS(d time.Duration) []byte {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if rec := p.fromPeer.take(); len(rec) > 0 {
			return rec
		}
		time.Sleep(2 * time.Millisecond)
	}
	panic("no peer TLS")
}

func (p *peapTestPeer) TakeTLS() []byte { return p.fromPeer.take() }

func (p *peapTestPeer) PushTLS(b []byte) {
	if len(b) == 0 {
		return
	}
	_, _ = p.toPeer.Write(b)
}

func (p *peapTestPeer) HandshakeDone() bool {
	if p.hsDone {
		return p.hsErr == nil
	}
	select {
	case err := <-p.hs:
		p.hsDone = true
		p.hsErr = err
		return err == nil
	default:
		return false
	}
}

func (p *peapTestPeer) ReadApp(d time.Duration) ([]byte, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2048)
	n, err := p.conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

func (p *peapTestPeer) WriteApp(b []byte) error {
	_, err := p.conn.Write(b)
	return err
}

package server

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

type scriptedAuth struct {
	dec aaa.RadiusAccessDecision
	err error
	got aaa.RadiusAccessAttempt
}

func (s *scriptedAuth) AuthenticateAccess(_ context.Context, in aaa.RadiusAccessAttempt) (aaa.RadiusAccessDecision, error) {
	s.got = in
	s.got.Evidence.Challenge = append([]byte(nil), in.Evidence.Challenge...)
	s.got.Evidence.Response = append([]byte(nil), in.Evidence.Response...)
	return s.dec, s.err
}

func TestAccessExtractRejects(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x33
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	chap := append([]byte{0x07}, make([]byte, 16)...)

	type tc struct {
		name   string
		attrs  attribute.RawSet
		want   string
		auth   *scriptedAuth
		called bool
	}
	authOK := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
	cases := []tc{
		{
			name:  "missing-username",
			attrs: attribute.RawSet{{Type: attribute.TypeUserPassword, Value: hidden}},
			want:  ReasonMissingUsername,
		},
		{
			name: "duplicate-username",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeUserName, Value: []byte("b")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			},
			want: ReasonMissingUsername,
		},
		{
			name: "pap-and-chap",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeUserPassword, Value: hidden},
				{Type: attribute.TypeCHAPPassword, Value: chap},
			},
			want: ReasonConflictingAuth,
		},
		{
			name: "chap-length",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeCHAPPassword, Value: []byte{1, 2, 3}},
			},
			want: ReasonCHAPPasswordLength,
		},
		{
			name:  "no-evidence",
			attrs: attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}},
			want:  ReasonUnsupportedMethod,
		},
		{
			name: "pap-default-deny",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			},
			want:   ReasonPolicy,
			auth:   authOK,
			called: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := tc.auth
			if auth == nil {
				auth = &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
			}
			in := signedAccessReq(t, ra, tc.attrs, true)
			res := Access{AAA: auth}.Handle(context.Background(), in)
			if res.Action != ActionReply || res.Reason != tc.want {
				t.Fatalf("got %+v want reason=%s", res, tc.want)
			}
			assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
			if tc.called != (auth.got.UserID != "") {
				t.Fatalf("authenticator called=%v user=%q", auth.got.UserID != "", auth.got.UserID)
			}
			if res.Response[0] == byte(codec.CodeAccessAccept) {
				t.Fatal("reject path must not Access-Accept")
			}
		})
	}
}

func TestAccessCHAPUsesChallengeOrRequestAuthenticator(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	for i := range ra {
		ra[i] = byte(i + 1)
	}
	id := byte(0x09)
	chal := []byte("chap-chal-16b!!")
	resp := credentials.CHAPResponse(id, []byte("secret"), chal)
	chap := append([]byte{id}, resp...)

	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeCHAPPassword, Value: chap},
		{Type: attribute.TypeCHAPChallenge, Value: chal},
	}, true)
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonPolicy {
		t.Fatalf("got %+v", res)
	}
	if auth.got.Evidence.Method != domain.AuthMethodCHAP || auth.got.Evidence.CHAPID != id {
		t.Fatalf("evidence=%+v", auth.got.Evidence)
	}
	if string(auth.got.Evidence.Challenge) != string(chal) {
		t.Fatalf("challenge=%q", auth.got.Evidence.Challenge)
	}

	auth = &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonBadCredentials}}
	in = signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeCHAPPassword, Value: chap},
	}, true)
	res = Access{AAA: auth}.Handle(context.Background(), in)
	if res.Reason != ReasonBadCredentials {
		t.Fatalf("got %+v", res)
	}
	if string(auth.got.Evidence.Challenge) != string(ra[:]) {
		t.Fatalf("fallback challenge=%x want %x", auth.got.Evidence.Challenge, ra[:])
	}
}

func TestAccessPermitEmitsAcceptWithProfileAttrs(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x44
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	var timeout [4]byte
	binary.BigEndian.PutUint32(timeout[:], 600)
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{
		Outcome:    aaa.RadiusAccessAccept,
		ReasonCode: aaa.AccessReasonOK,
		ReplyAttributes: attribute.RawSet{
			{Type: attribute.TypeSessionTimeout, Value: timeout[:]},
		},
	}}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
		{Type: attribute.TypeProxyState, Value: []byte("ps")},
	}, true)
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("permit must Access-Accept: %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessAccept, 1, ra, testSecret)
	pkt, err := codec.Decode(res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attributes.Len() < 3 || pkt.Attributes[0].Type != attribute.TypeMessageAuthenticator {
		t.Fatalf("MA first: %+v", pkt.Attributes)
	}
	if pkt.Attributes[1].Type != attribute.TypeProxyState || string(pkt.Attributes[1].Value) != "ps" {
		t.Fatalf("Proxy-State second: %+v", pkt.Attributes)
	}
	if pkt.Attributes[2].Type != attribute.TypeSessionTimeout || binary.BigEndian.Uint32(pkt.Attributes[2].Value) != 600 {
		t.Fatalf("Session-Timeout: %+v", pkt.Attributes)
	}
}

func TestAccessIllegalAcceptAttrsFailClosed(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x45
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{
		Outcome:    aaa.RadiusAccessAccept,
		ReasonCode: aaa.AccessReasonOK,
		ReplyAttributes: attribute.RawSet{
			{Type: attribute.TypeNASIPAddress, Value: []byte{192, 0, 2, 1}},
		},
	}}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
	}, true)
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonInternal {
		t.Fatalf("illegal accept attrs must reject: %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
}

func TestAccessDiscardsInvalidMA(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x55
	in := signedAccessReq(t, ra, attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}}, true)
	in.Declared[len(in.Declared)-1] ^= 0xff
	res := Access{}.Handle(context.Background(), in)
	if res.Action != ActionDiscard || res.Reason != ReasonInvalidMA {
		t.Fatalf("got %+v", res)
	}
}

func signedAccessReq(t *testing.T, ra [16]byte, attrs attribute.RawSet, requireMA bool) Request {
	t.Helper()
	pkt := codec.Packet{Code: codec.CodeAccessRequest, Identifier: 1, Authenticator: ra, Attributes: attrs}
	declared := signRequestMA(t, testSecret, pkt)
	dec, err := codec.Decode(declared)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		Role:                        domain.RoleAccess,
		Packet:                      dec,
		Declared:                    declared,
		Secret:                      testSecret,
		RequireMessageAuthenticator: requireMA,
		AllowedMethods:              []string{methodPAP, methodCHAP},
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

type v1Vector struct {
	ID                 byte   `json:"id"`
	MSCHAPChallengeHex string `json:"ms_chap_challenge_hex"`
	MSCHAPResponseHex  string `json:"ms_chap_response_hex"`
}

type v2Vector struct {
	ID                 byte   `json:"id"`
	MSCHAPChallengeHex string `json:"ms_chap_challenge_hex"`
	MSCHAP2ResponseHex string `json:"ms_chap2_response_hex"`
}

func loadV1(t *testing.T) v1Vector {
	t.Helper()
	return loadMSCHAPJSON[v1Vector](t, "rfc2433-v1-radius.json")
}

func loadV2(t *testing.T) v2Vector {
	t.Helper()
	return loadMSCHAPJSON[v2Vector](t, "rfc2759-v2-radius.json")
}

func loadMSCHAPJSON[T any](t *testing.T, name string) T {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for i := 0; i < 10; i++ {
		cand := filepath.Join(dir, "testdata", "protocol", "radius", "mschap", name)
		if _, err := os.Stat(cand); err == nil {
			path = cand
			break
		}
		dir = filepath.Dir(dir)
	}
	if path == "" {
		t.Fatalf("missing %s", name)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func msAttrs(t *testing.T, chal, resp []byte, v2 bool) attribute.RawSet {
	t.Helper()
	c, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAPChallenge, chal)
	if err != nil {
		t.Fatal(err)
	}
	typ := attribute.VendorTypeMSCHAPResponse
	if v2 {
		typ = attribute.VendorTypeMSCHAP2Response
	}
	r, err := attribute.MicrosoftVSA(typ, resp)
	if err != nil {
		t.Fatal(err)
	}
	return attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("User")},
		c, r,
	}
}

func TestAccessExtractMSCHAPv1Maps50To49(t *testing.T) {
	t.Parallel()
	v := loadV1(t)
	chal := mustHex(t, v.MSCHAPChallengeHex)
	resp := mustHex(t, v.MSCHAPResponseHex)
	var ra [16]byte
	ra[0] = 0x21
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
	in := signedAccessReq(t, ra, msAttrs(t, chal, resp, false), true)
	in.AllowedMethods = []string{methodPAP, methodCHAP, methodMSCHAPv1, methodMSCHAPv2}
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Action != ActionReply {
		t.Fatalf("got %+v", res)
	}
	if auth.got.Evidence.Method != domain.AuthMethodMSCHAPv1 || auth.got.Evidence.CHAPID != v.ID {
		t.Fatalf("evidence=%+v", auth.got.Evidence)
	}
	if !bytes.Equal(auth.got.Evidence.Challenge, chal) {
		t.Fatalf("challenge=%x", auth.got.Evidence.Challenge)
	}
	want := mapMSCHAPv1(resp)
	if !bytes.Equal(auth.got.Evidence.Response, want) {
		t.Fatalf("mapped %x want %x", auth.got.Evidence.Response, want)
	}
	if len(auth.got.Evidence.Response) != 49 {
		t.Fatalf("mapped len=%d", len(auth.got.Evidence.Response))
	}
}

func TestAccessExtractMSCHAPv2Maps50To49(t *testing.T) {
	t.Parallel()
	v := loadV2(t)
	chal := mustHex(t, v.MSCHAPChallengeHex)
	resp := mustHex(t, v.MSCHAP2ResponseHex)
	var ra [16]byte
	ra[0] = 0x22
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
	in := signedAccessReq(t, ra, msAttrs(t, chal, resp, true), true)
	in.AllowedMethods = []string{methodPAP, methodCHAP, methodMSCHAPv1, methodMSCHAPv2}
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Reason != ReasonPolicy {
		t.Fatalf("got %+v", res)
	}
	if auth.got.Evidence.Method != domain.AuthMethodMSCHAPv2 || auth.got.Evidence.CHAPID != v.ID {
		t.Fatalf("evidence=%+v", auth.got.Evidence)
	}
	mapped, ok := mapMSCHAPv2(resp)
	if !ok || !bytes.Equal(auth.got.Evidence.Response, mapped) {
		t.Fatalf("mapped %x ok=%v", auth.got.Evidence.Response, ok)
	}
}

func TestAccessMSCHAPConflictMatrix(t *testing.T) {
	t.Parallel()
	v := loadV1(t)
	chal := mustHex(t, v.MSCHAPChallengeHex)
	resp := mustHex(t, v.MSCHAPResponseHex)
	v2 := loadV2(t)
	v2resp := mustHex(t, v2.MSCHAP2ResponseHex)
	v2chal := mustHex(t, v2.MSCHAPChallengeHex)
	var ra [16]byte
	ra[0] = 0x23
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	ms := msAttrs(t, chal, resp, false)
	chap := append([]byte{0x07}, make([]byte, 16)...)
	v2raw, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAP2Response, v2resp)
	if err != nil {
		t.Fatal(err)
	}
	v2chalRaw, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAPChallenge, v2chal)
	if err != nil {
		t.Fatal(err)
	}
	shortChal, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAPChallenge, chal[:4])
	if err != nil {
		t.Fatal(err)
	}
	v1respRaw, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAPResponse, resp)
	if err != nil {
		t.Fatal(err)
	}
	malformed, err := (attribute.VSA{Vendor: attribute.VendorMicrosoft, Payload: []byte{0x01, 0x05}}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	nonzero := append([]byte(nil), v2resp...)
	copy(nonzero[18:26], []byte{1, 0, 0, 0, 0, 0, 0, 0})
	badReserved, err := attribute.MicrosoftVSA(attribute.VendorTypeMSCHAP2Response, nonzero)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		attrs attribute.RawSet
		want  string
	}{
		{
			name: "pap-plus-mschap",
			attrs: append(attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				{Type: attribute.TypeUserPassword, Value: hidden},
			}, ms[1:]...),
			want: ReasonConflictingAuth,
		},
		{
			name: "chap-plus-mschap",
			attrs: append(attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				{Type: attribute.TypeCHAPPassword, Value: chap},
			}, ms[1:]...),
			want: ReasonConflictingAuth,
		},
		{
			name: "eap-plus-mschap",
			attrs: append(attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				{Type: attribute.TypeEAPMessage, Value: []byte{2, 1, 0, 5, 1}},
			}, ms[1:]...),
			want: ReasonConflictingAuth,
		},
		{
			name: "v1-and-v2",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				v2chalRaw, v1respRaw, v2raw,
			},
			want: ReasonConflictingAuth,
		},
		{
			name: "v1-wrong-challenge-len",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				shortChal, v1respRaw,
			},
			want: ReasonConflictingAuth,
		},
		{
			name: "malformed-tlv",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				malformed,
			},
			want: ReasonConflictingAuth,
		},
		{
			name: "v2-nonzero-reserved",
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("User")},
				v2chalRaw, badReserved,
			},
			want: ReasonConflictingAuth,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPolicy}}
			in := signedAccessReq(t, ra, tc.attrs, true)
			in.AllowedMethods = []string{methodPAP, methodCHAP, methodMSCHAPv1, methodMSCHAPv2}
			res := Access{AAA: auth}.Handle(context.Background(), in)
			if res.Reason != tc.want {
				t.Fatalf("got %+v want %s", res, tc.want)
			}
			if auth.got.UserID != "" {
				t.Fatal("AAA must not be called on conflict")
			}
		})
	}
}

func TestAccessMSCHAPOptInDefaultRejects(t *testing.T) {
	t.Parallel()
	v := loadV1(t)
	var ra [16]byte
	ra[0] = 0x24
	in := signedAccessReq(t, ra, msAttrs(t, mustHex(t, v.MSCHAPChallengeHex), mustHex(t, v.MSCHAPResponseHex), false), true)
	in.AllowedMethods = []string{methodPAP, methodCHAP}
	res := Access{AAA: &scriptedAuth{}}.Handle(context.Background(), in)
	if res.Reason != ReasonUnsupportedMethod {
		t.Fatalf("default methods must reject MS-CHAP: %+v", res)
	}
}

func TestAccessMSCHAPMustChangeHasNoExtraAttrs(t *testing.T) {
	t.Parallel()
	v := loadV1(t)
	var ra [16]byte
	ra[0] = 0x25
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: aaa.AccessReasonPasswordChangeRequired}}
	in := signedAccessReq(t, ra, msAttrs(t, mustHex(t, v.MSCHAPChallengeHex), mustHex(t, v.MSCHAPResponseHex), false), true)
	in.AllowedMethods = []string{methodMSCHAPv1}
	res := Access{AAA: auth}.Handle(context.Background(), in)
	if res.Reason != ReasonPasswordChangeRequired {
		t.Fatalf("got %+v", res)
	}
	assertSigned(t, res.Response, codec.CodeAccessReject, 1, ra, testSecret)
	pkt, err := codec.Decode(res.Response)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range pkt.Attributes {
		if a.Type == attribute.TypeVendorSpecific {
			t.Fatal("must_change must not emit MS-CHAP-Error or extra VSAs")
		}
		if a.Type != attribute.TypeMessageAuthenticator {
			t.Fatalf("unexpected attr type %d", a.Type)
		}
	}
}

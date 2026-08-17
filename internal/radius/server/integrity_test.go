package server

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

func TestCheckAccessIntegrityMAAndProxyState(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x11

	type tc struct {
		name      string
		requireMA bool
		limitPS   bool
		attrs     attribute.RawSet
		signMA    bool
		tamperMA  bool
		want      string
	}
	cases := []tc{
		{
			name:      "missing-ma-required",
			requireMA: true,
			attrs:     attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}},
			want:      ReasonMissingMA,
		},
		{
			name:      "valid-ma",
			requireMA: true,
			signMA:    true,
			attrs:     attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}},
		},
		{
			name:      "invalid-ma",
			requireMA: true,
			signMA:    true,
			tamperMA:  true,
			attrs:     attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}},
			want:      ReasonInvalidMA,
		},
		{
			name:      "duplicate-ma",
			requireMA: true,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
				{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
			},
			want: ReasonInvalidMA,
		},
		{
			name:      "eap-without-ma",
			requireMA: false,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeEAPMessage, Value: []byte{1, 0, 0, 4}},
			},
			want: ReasonEAPWithoutMA,
		},
		{
			name:      "proxy-state-without-ma-limited",
			requireMA: false,
			limitPS:   true,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeProxyState, Value: []byte("ps")},
			},
			want: ReasonProxyStateWithoutMA,
		},
		{
			name:      "compat-missing-ma-no-proxy",
			requireMA: false,
			limitPS:   true,
			attrs:     attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("a")}},
		},
		{
			name:      "compat-proxy-without-limit",
			requireMA: false,
			limitPS:   false,
			attrs: attribute.RawSet{
				{Type: attribute.TypeUserName, Value: []byte("a")},
				{Type: attribute.TypeProxyState, Value: []byte("ps")},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := accessIntegrityRequest(t, ra, tc.attrs, tc.requireMA, tc.limitPS, tc.signMA)
			if tc.tamperMA && len(in.Declared) > codec.HeaderSize+2 {
				in.Declared[len(in.Declared)-1] ^= 0xff
			}
			if got := CheckIntegrity(in); got != tc.want {
				t.Fatalf("reason=%q want %q", got, tc.want)
			}
		})
	}
}

func TestCheckDynAuthIntegrityAlwaysRequiresMA(t *testing.T) {
	t.Parallel()
	var ra [16]byte
	ra[0] = 0x33
	missing := Request{
		Role:                        domain.RoleDynamicAuthorization,
		Packet:                      codec.Packet{Code: codec.CodeDisconnectRequest, Identifier: 1, Authenticator: ra},
		Declared:                    mustEncode(t, codec.Packet{Code: codec.CodeDisconnectRequest, Identifier: 1, Authenticator: ra}),
		Secret:                      testSecret,
		RequireMessageAuthenticator: false,
	}
	if got := CheckIntegrity(missing); got != ReasonMissingMA {
		t.Fatalf("missing MA: %s", got)
	}

	signed := signRequestMA(t, testSecret, codec.Packet{
		Code:          codec.CodeCoARequest,
		Identifier:    2,
		Authenticator: ra,
		Attributes:    attribute.RawSet{{Type: attribute.TypeUserName, Value: []byte("lab-admin")}},
	})
	dec, err := codec.Decode(signed)
	if err != nil {
		t.Fatal(err)
	}
	ok := Request{Role: domain.RoleDynamicAuthorization, Packet: dec, Declared: signed, Secret: testSecret}
	if got := CheckIntegrity(ok); got != "" {
		t.Fatalf("valid MA: %s", got)
	}
	signed[len(signed)-1] ^= 0xff
	dec, err = codec.Decode(signed)
	if err != nil {
		t.Fatal(err)
	}
	bad := Request{Role: domain.RoleDynamicAuthorization, Packet: dec, Declared: signed, Secret: testSecret}
	if got := CheckIntegrity(bad); got != ReasonInvalidMA {
		t.Fatalf("invalid MA: %s", got)
	}
}

func TestCheckAccountingIntegrityValidatesPresentMA(t *testing.T) {
	t.Parallel()
	pkt := codec.Packet{Code: codec.CodeAccountingRequest, Identifier: 1}
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := crypto.AccountingRequestAuthenticator(testSecret, raw)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Authenticator = auth
	in := Request{
		Role:     domain.RoleAccounting,
		Packet:   pkt,
		Declared: mustEncode(t, pkt),
		Secret:   testSecret,
	}
	if got := CheckIntegrity(in); got != "" {
		t.Fatalf("no MA: %s", got)
	}

	signed := signRequestMA(t, testSecret, codec.Packet{
		Code:          codec.CodeAccountingRequest,
		Identifier:    1,
		Authenticator: auth,
		Attributes:    attribute.RawSet{{Type: attribute.TypeAcctStatusType, Value: []byte{0, 0, 0, 1}}},
	})
	dec, err := codec.Decode(signed)
	if err != nil {
		t.Fatal(err)
	}
	in = Request{Role: domain.RoleAccounting, Packet: dec, Declared: signed, Secret: testSecret}
	if got := CheckIntegrity(in); got != "" {
		t.Fatalf("valid MA: %s", got)
	}
	signed[len(signed)-1] ^= 0xff
	dec, err = codec.Decode(signed)
	if err != nil {
		t.Fatal(err)
	}
	in = Request{Role: domain.RoleAccounting, Packet: dec, Declared: signed, Secret: testSecret}
	if got := CheckIntegrity(in); got != ReasonInvalidMA {
		t.Fatalf("invalid MA: %s", got)
	}
}

func accessIntegrityRequest(t *testing.T, ra [16]byte, attrs attribute.RawSet, requireMA, limitPS, addMA bool) Request {
	t.Helper()
	pkt := codec.Packet{Code: codec.CodeAccessRequest, Identifier: 1, Authenticator: ra, Attributes: attrs}
	var declared []byte
	if addMA && !hasMA(attrs) {
		declared = signRequestMA(t, testSecret, pkt)
		dec, err := codec.Decode(declared)
		if err != nil {
			t.Fatal(err)
		}
		pkt = dec
	} else {
		declared = mustEncode(t, pkt)
	}
	return Request{
		Role:                        domain.RoleAccess,
		Packet:                      pkt,
		Declared:                    declared,
		Secret:                      testSecret,
		RequireMessageAuthenticator: requireMA,
		LimitProxyState:             limitPS,
	}
}

func hasMA(attrs attribute.RawSet) bool {
	return attrs.AllOf(attribute.TypeMessageAuthenticator).Len() > 0
}

func mustEncode(t *testing.T, pkt codec.Packet) []byte {
	t.Helper()
	raw, err := codec.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signRequestMA(t *testing.T, secret []byte, pkt codec.Packet) []byte {
	t.Helper()
	attrs := append(attribute.RawSet(nil), pkt.Attributes...)
	attrs = append(attrs, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)})
	pkt.Attributes = attrs
	raw := mustEncode(t, pkt)
	mac, err := crypto.MessageAuthenticator(secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	off := codec.HeaderSize
	for off+2 <= len(raw) {
		alen := int(raw[off+1])
		if raw[off] == attribute.TypeMessageAuthenticator {
			copy(raw[off+2:off+18], mac[:])
			return raw
		}
		off += alen
	}
	t.Fatal("MA missing")
	return raw
}

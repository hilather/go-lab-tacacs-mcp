package server

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

func BenchmarkRadiusAccessPAP_NoKDF(b *testing.B) {
	var ra [16]byte
	ra[0] = 0x7a
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		b.Fatal(err)
	}
	pkt := codec.Packet{
		Code:          codec.CodeAccessRequest,
		Identifier:    1,
		Authenticator: ra,
		Attributes: attribute.RawSet{
			{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
			{Type: attribute.TypeUserPassword, Value: hidden},
			{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)},
		},
	}
	raw, err := codec.Encode(pkt)
	if err != nil {
		b.Fatal(err)
	}
	mac, err := crypto.MessageAuthenticator(testSecret, raw)
	if err != nil {
		b.Fatal(err)
	}
	off := codec.HeaderSize
	for off+2 <= len(raw) {
		alen := int(raw[off+1])
		if raw[off] == attribute.TypeMessageAuthenticator {
			copy(raw[off+2:off+18], mac[:])
			break
		}
		off += alen
	}
	dec, err := codec.Decode(raw)
	if err != nil {
		b.Fatal(err)
	}
	auth := &scriptedAuth{dec: aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessAccept, ReasonCode: aaa.AccessReasonOK}}
	h := Access{AAA: auth}
	in := Request{
		Role:                        domain.RoleAccess,
		Packet:                      dec,
		Declared:                    raw,
		Secret:                      testSecret,
		RequireMessageAuthenticator: true,
		AllowedMethods:              []string{methodPAP, methodCHAP},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := h.Handle(context.Background(), in)
		if res.Action != ActionReply || res.Reason != ReasonOK {
			b.Fatalf("%+v", res)
		}
	}
}

func BenchmarkRadiusAccountingRequest(b *testing.B) {
	BenchmarkAccountingHandle(b)
}

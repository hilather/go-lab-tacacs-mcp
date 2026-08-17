package server

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
)

type carrierAAA struct {
	got domain.Carrier
}

func (c *carrierAAA) AuthenticateAccess(_ context.Context, in aaa.RadiusAccessAttempt) (aaa.RadiusAccessDecision, error) {
	c.got = in.Context.Carrier
	return aaa.RadiusAccessDecision{Outcome: aaa.RadiusAccessReject, ReasonCode: ReasonBadCredentials}, nil
}

func TestAccessUsesRequestCarrier(t *testing.T) {
	t.Parallel()
	stub := &carrierAAA{}
	var ra [16]byte
	ra[0] = 1
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
	}, true)
	in.Carrier = domain.CarrierRADIUSTLS
	_ = Access{AAA: stub}.Handle(context.Background(), in)
	if stub.got != domain.CarrierRADIUSTLS {
		t.Fatalf("carrier=%s", stub.got)
	}
}

func TestAccessDefaultsEmptyCarrierToUDP(t *testing.T) {
	t.Parallel()
	stub := &carrierAAA{}
	var ra [16]byte
	ra[0] = 2
	hidden, err := crypto.HideUserPassword(testSecret, ra, []byte("labpass1!"))
	if err != nil {
		t.Fatal(err)
	}
	in := signedAccessReq(t, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeUserPassword, Value: hidden},
	}, true)
	_ = Access{AAA: stub}.Handle(context.Background(), in)
	if stub.got != domain.CarrierRADIUSUDP {
		t.Fatalf("carrier=%s", stub.got)
	}
}

var _ AccessAuthenticator = (*carrierAAA)(nil)

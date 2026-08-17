package testclient

import (
	"crypto/rand"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestDynAuthRequestRoundTripMA(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	wire, err := EncodeDynAuthRequest(secret, DynAuthRequest{
		Code:          codec.DisconnectRequest,
		Identifier:    7,
		UserName:      "lab-admin",
		AcctSessionID: "0001",
	}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodeDynAuthRequest(secret, wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Code != codec.DisconnectRequest || pkt.Identifier != 7 {
		t.Fatalf("%+v", pkt)
	}
	if pkt.Attrs[0].Type != codec.TypeMessageAuthenticator {
		t.Fatal("MA first")
	}
}

func TestDynAuthRequestMALastRoundTrip(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	wire, err := EncodeDynAuthRequest(secret, DynAuthRequest{
		Code:          codec.DisconnectRequest,
		Identifier:    8,
		AcctSessionID: "0001",
		MALast:        true,
	}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodeDynAuthRequest(secret, wire)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Attrs[0].Type == codec.TypeMessageAuthenticator {
		t.Fatal("MA should be last")
	}
	if pkt.Attrs[len(pkt.Attrs)-1].Type != codec.TypeMessageAuthenticator {
		t.Fatal("expected MA last")
	}
}

func TestDynAuthRequestRejectsBadMA(t *testing.T) {
	t.Parallel()
	secret := []byte("LabSecret-16chars!")
	wire, err := EncodeDynAuthRequest(secret, DynAuthRequest{Code: codec.CoARequest, UserName: "u"}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire[codec.HeaderLen+2] ^= 0xff
	if _, err := DecodeDynAuthRequest(secret, wire); err == nil {
		t.Fatal("expected MA failure")
	}
}

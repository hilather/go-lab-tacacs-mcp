package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/crypto"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestInboundDisconnectMissNAK503(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x21
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeAcctSessionID, Value: []byte("missing")},
	})
	res := h.Handle(context.Background(), in)
	if res.Action != ActionReply {
		t.Fatalf("action=%v reason=%s", res.Action, res.Reason)
	}
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectNAK || reply.ErrorCause != ErrorCauseSessionContextNotFound {
		t.Fatalf("reply=%+v", reply)
	}
}

func TestInboundDisconnectHitDeletesIndex(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "c", UserID: "u", SessionID: "s1",
	}) {
		t.Fatal("start")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x22
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeAcctSessionID, Value: []byte("s1")},
	})
	in.ClientID = "c"
	in.EndpointID = "ep"
	res := h.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("res=%+v", res)
	}
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("code=%s", reply.Code)
	}
	if idx.Len() != 0 {
		t.Fatal("index row must be deleted")
	}
}

func TestInboundCoAUnsupportedAttrNAK401(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "c", SessionID: "s1",
	}) {
		t.Fatal("start")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x23
	in := dynAuthRequest(t, codec.CodeCoARequest, ra, attribute.RawSet{
		{Type: attribute.TypeAcctSessionID, Value: []byte("s1")},
		{Type: attribute.TypeFramedIPAddress, Value: []byte{192, 0, 2, 1}},
	})
	in.ClientID = "c"
	in.EndpointID = "ep"
	res := h.Handle(context.Background(), in)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.CoANAK || reply.ErrorCause != ErrorCauseUnsupportedAttribute {
		t.Fatalf("reply=%+v", reply)
	}
	if _, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "ep", AcctSessionID: "s1"}); !ok {
		t.Fatal("unsupported CoA must not delete the row")
	}
}

func dynAuthRequest(t *testing.T, code codec.Code, ra [16]byte, rest attribute.RawSet) Request {
	t.Helper()
	attrs := make(attribute.RawSet, 0, 1+rest.Len())
	attrs = append(attrs, attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)})
	attrs = append(attrs, rest...)
	pkt := codec.Packet{Code: code, Identifier: 1, Authenticator: ra, Attributes: attrs}
	raw := mustEncode(t, pkt)
	mac, err := crypto.MessageAuthenticator(testSecret, raw)
	if err != nil {
		t.Fatal(err)
	}
	copy(raw[codec.HeaderSize+2:codec.HeaderSize+18], mac[:])
	dec, err := codec.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		Role:                        domain.RoleDynamicAuthorization,
		Packet:                      dec,
		Declared:                    raw,
		Secret:                      testSecret,
		RequireMessageAuthenticator: true,
	}
}

func mustSessionIndex(t *testing.T) *radiusruntime.SessionIndex {
	t.Helper()
	idx, err := radiusruntime.NewSessionIndex(radiusruntime.Options{
		MaxEntries: 16,
		MaxBytes:   64 << 10,
		TTL:        time.Hour,
		Entropy:    bytes.NewReader(bytes.Repeat([]byte("0123456789abcdef"), 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

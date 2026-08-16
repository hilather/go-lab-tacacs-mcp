package server

import (
	"bytes"
	"context"
	"net"
	"net/netip"
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

func TestInboundMALastACKsAndNeverOriginates(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "u", SessionID: "s-ma-last",
	}) {
		t.Fatal("start")
	}
	dialed := 0
	h := DynamicAuth{
		Sessions: idx,
		Originator: &Originator{
			Dial: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
				dialed++
				return nil, nil, errUnexpected("forward", "inbound DAS must not originate")
			},
		},
	}
	var ra [16]byte
	ra[0] = 0x24
	in := dynAuthRequestMALast(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeAcctSessionID, Value: []byte("s-ma-last")},
	})
	res := h.Handle(context.Background(), in)
	if res.Action != ActionReply || res.Reason != ReasonOK {
		t.Fatalf("MA last must ACK, got %+v", res)
	}
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("code=%s", reply.Code)
	}
	if dialed != 0 {
		t.Fatal("inbound DAS must never call Originator.Dial")
	}
}

func TestInboundMultipleSessionsNAK508(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "a",
	}) || !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "b",
	}) {
		t.Fatal("starts")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x25
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
	})
	res := h.Handle(context.Background(), in)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectNAK || reply.ErrorCause != ErrorCauseMultipleSessionSelection {
		t.Fatalf("reply=%+v", reply)
	}
	if idx.Len() != 2 {
		t.Fatalf("ambiguous NAK must not delete rows: %d", idx.Len())
	}
}

func TestInboundUserNameNASIPIdentification(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	nas := netip.MustParseAddr("192.0.2.10")
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "with-nas", NASIP: nas,
	}) {
		t.Fatal("start")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x26
	hit := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeNASIPAddress, Value: nas4(nas)},
	})
	res := h.Handle(context.Background(), hit)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("matching NAS-IP must ACK, got %+v", reply)
	}
}

func TestInboundWrongNASIPAgainstEmptyRecordNAK503(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "no-nas",
	}) {
		t.Fatal("start")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x27
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeNASIPAddress, Value: []byte{192, 0, 2, 99}},
	})
	res := h.Handle(context.Background(), in)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectNAK || reply.ErrorCause != ErrorCauseSessionContextNotFound {
		t.Fatalf("empty record NAS-IP must not match query NAS-IP: %+v", reply)
	}
	if idx.Len() != 1 {
		t.Fatal("503 must not delete the row")
	}
}

func TestInboundNamedNASIPIsUniqueAmongMixedRows(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	nas := netip.MustParseAddr("192.0.2.10")
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "with-nas", NASIP: nas,
	}) || !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "ep", ClientID: "nas", UserID: "lab-admin", SessionID: "no-nas",
	}) {
		t.Fatal("starts")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x28
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeUserName, Value: []byte("lab-admin")},
		{Type: attribute.TypeNASIPAddress, Value: nas4(nas)},
	})
	res := h.Handle(context.Background(), in)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("named NAS-IP must uniquely hit, got %+v", reply)
	}
	if _, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "ep", AcctSessionID: "with-nas"}); ok {
		t.Fatal("named row should be deleted")
	}
	if _, ok := idx.LookupKey(radiusruntime.SessionKey{EndpointID: "ep", AcctSessionID: "no-nas"}); !ok {
		t.Fatal("unmatched empty-NAS row must remain")
	}
}

func TestInboundToolClientCanTargetNASSession(t *testing.T) {
	t.Parallel()
	idx := mustSessionIndex(t)
	if !idx.Apply(radiusruntime.AcctEvent{
		Kind: radiusruntime.EventStart, EndpointID: "nas-udp", ClientID: "nas", UserID: "lab-admin", SessionID: "cross",
	}) {
		t.Fatal("start")
	}
	h := DynamicAuth{Sessions: idx}
	var ra [16]byte
	ra[0] = 0x29
	in := dynAuthRequest(t, codec.CodeDisconnectRequest, ra, attribute.RawSet{
		{Type: attribute.TypeAcctSessionID, Value: []byte("cross")},
	})
	in.ClientID = "rfc5176-tool"
	in.EndpointID = "tool-udp"
	res := h.Handle(context.Background(), in)
	reply, err := testclient.DecodeDynAuthReply(testSecret, ra, res.Response)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != tcodec.DisconnectACK {
		t.Fatalf("tool client must ACK a NAS session by Acct-Session-Id, got %+v", reply)
	}
}

func dynAuthRequest(t *testing.T, code codec.Code, ra [16]byte, rest attribute.RawSet) Request {
	t.Helper()
	return dynAuthRequestOrder(t, code, ra, rest, false)
}

func dynAuthRequestMALast(t *testing.T, code codec.Code, ra [16]byte, rest attribute.RawSet) Request {
	t.Helper()
	return dynAuthRequestOrder(t, code, ra, rest, true)
}

func dynAuthRequestOrder(t *testing.T, code codec.Code, ra [16]byte, rest attribute.RawSet, maLast bool) Request {
	t.Helper()
	ma := attribute.Raw{Type: attribute.TypeMessageAuthenticator, Value: make([]byte, 16)}
	attrs := make(attribute.RawSet, 0, 1+rest.Len())
	if !maLast {
		attrs = append(attrs, ma)
	}
	attrs = append(attrs, rest...)
	if maLast {
		attrs = append(attrs, ma)
	}
	pkt := codec.Packet{Code: code, Identifier: 1, Authenticator: ra, Attributes: attrs}
	raw := mustEncode(t, pkt)
	mac, err := crypto.MessageAuthenticator(testSecret, raw)
	if err != nil {
		t.Fatal(err)
	}
	off := codec.HeaderSize
	for off+2 <= len(raw) {
		n := int(raw[off+1])
		if raw[off] == attribute.TypeMessageAuthenticator {
			copy(raw[off+2:off+18], mac[:])
			break
		}
		off += n
	}
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

func nas4(a netip.Addr) []byte {
	b := a.As4()
	return b[:]
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

package domain

import (
	"net/netip"
	"testing"
	"time"
)

func TestRequestContextHoldsNeutralRequestMetadata(t *testing.T) {
	t.Parallel()
	peer := netip.MustParseAddrPort("192.0.2.10:1812")
	at := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	ctx := RequestContext{
		Protocol:         ProtocolRADIUS,
		Carrier:          CarrierRADIUSUDP,
		ListenerRole:     RoleAccess,
		ListenerID:       "radius-access",
		ClientID:         "nas-1",
		EndpointID:       "nas-1-access",
		Peer:             peer,
		SnapshotRevision: 7,
		CorrelationID:    "corr-1",
		ReceivedAt:       at,
	}
	if ctx.Protocol != ProtocolRADIUS || ctx.Carrier != CarrierRADIUSUDP || ctx.ListenerRole != RoleAccess {
		t.Fatalf("%+v", ctx)
	}
	if ctx.ListenerID != "radius-access" || ctx.ClientID != "nas-1" || ctx.EndpointID != "nas-1-access" {
		t.Fatalf("%+v", ctx)
	}
	if ctx.Peer != peer || ctx.SnapshotRevision != 7 || ctx.CorrelationID != "corr-1" || !ctx.ReceivedAt.Equal(at) {
		t.Fatalf("%+v", ctx)
	}

	tacacs := RequestContext{
		Protocol:     ProtocolTACACS,
		Carrier:      CarrierTACACSLegacyTCP,
		ListenerRole: RoleAAA,
		ListenerID:   "legacy",
	}
	if tacacs.ListenerRole != RoleAAA || tacacs.Carrier != CarrierTACACSLegacyTCP {
		t.Fatalf("TACACS socket must use RoleAAA: %+v", tacacs)
	}
}

package domain

import (
	"net/netip"
	"time"
)

// RequestContext is adapter-filled request metadata after source-client resolution.
// CorrelationID is an opaque ULID/UUIDv4 from injectable entropy; it is not a
// RADIUS Identifier or authenticator. Usernames, NAS identifiers, IPs, and
// attribute values must never become metric labels.
type RequestContext struct {
	Protocol         Protocol
	Carrier          Carrier
	ListenerRole     ListenerRole
	ListenerID       string
	ClientID         string
	EndpointID       string
	Peer             netip.AddrPort
	SnapshotRevision Revision
	CorrelationID    string
	ReceivedAt       time.Time
}

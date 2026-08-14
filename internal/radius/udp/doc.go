// Package udp serves RADIUS/UDP access and accounting sockets.
//
// Receive is bounded (queue + worker pool + per-source rate). Source IP
// is resolved against the snapshot RADIUSIndex before any secret work.
// Unknown or ambiguous clients are silently discarded. The retransmission
// cache keys endpoint, role, source, socket, code, identifier, request
// authenticator, and declared-packet digest.
//
// This package may import a snapshot pointer, the RADIUS server adapter,
// runtime, and observability. It must not import TACACS, credentials,
// policy evaluation, or API adapters.
package udp

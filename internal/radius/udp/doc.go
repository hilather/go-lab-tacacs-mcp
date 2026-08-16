// Package udp serves RADIUS/UDP access, accounting, and optional dynauth sockets.
//
// Receive is bounded (queue + worker pool + per-source rate). Source IP
// is resolved against the snapshot RADIUSIndex before any secret work.
// Unknown or ambiguous clients are silently discarded. The retransmission
// cache keys endpoint, role, source, socket, code, identifier, request
// authenticator, and declared-packet digest. Accounting also keeps a
// semantic journal that excludes Acct-Delay-Time (exact retries and
// delay-time retries share one event; interim counters are not collapsed).
//
// This package may import a snapshot pointer, the RADIUS server adapter,
// runtime, and observability. It must not import TACACS, aaa, credentials,
// policy evaluation, or API adapters.
package udp

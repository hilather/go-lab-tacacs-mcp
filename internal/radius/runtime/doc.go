// Package runtime holds carrier-neutral in-process RADIUS tables.
//
// ChallengeStore is shared by RADIUS/UDP and (later) RADIUS/TLS listeners.
// It is process memory only: restart and runtime.reset wipe it. Listener
// Close must not drop the store while another carrier is still up.
//
// This package must not import radius/udp or radius/tls.
package runtime

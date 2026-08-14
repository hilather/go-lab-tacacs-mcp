// Package udp will serve RADIUS/UDP access and accounting sockets.
//
// It may import a snapshot pointer and the RADIUS server adapter. It
// must not import TACACS, credentials, policy evaluation, or API adapters.
// There is no production listener here.
package udp

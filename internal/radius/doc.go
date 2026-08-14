// Package radius holds RADIUS transport adapters, the packet codec,
// and related types as a peer of package tacacs.
//
// Wire types stay in this tree. This package must not import TACACS,
// HTTP, API adapters, config, or state. UDP listeners live in package
// udp and use a stub handler (Access-Reject / Accounting-Response).
// These packages do not advertise complete RADIUS.
package radius

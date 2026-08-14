// Package radius will hold RADIUS transport adapters, the packet codec,
// and related types as a peer of package tacacs.
//
// Wire types stay in this tree. This package must not import TACACS,
// HTTP, API adapters, config, or state. There is no production listener here.
package radius

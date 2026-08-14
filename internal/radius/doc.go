// Package radius holds RADIUS transport adapters, the packet codec,
// and related types as a peer of package tacacs.
//
// Wire types stay in this tree. This package must not import TACACS,
// HTTP, API adapters, config, or state. There is no production listener here.
// The codec implements packet framing. Package attribute holds raw TLVs
// and the built-in IETF MVP dictionary. Crypto primitives live in package
// crypto. These packages do not advertise complete RADIUS.
package radius

// Package attribute holds RADIUS raw TLV attributes and Vendor-Specific framing.
//
// This package is wire framing only: ordered, duplicate-preserving, binary-safe
// Raw values. It does not apply a named dictionary, hide User-Password, or
// validate authenticators. Type 26 is vendor-id plus an opaque payload.
//
// This package must not import the RADIUS codec, crypto, server, UDP, TACACS,
// config, state, AAA, API adapters, HTTP, events, or observability.
package attribute

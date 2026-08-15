// Package attribute holds RADIUS raw TLV attributes, Vendor-Specific framing,
// and the immutable built-in IETF MVP dictionary.
//
// Raw values stay ordered, duplicate-preserving, and binary-safe. Unknown
// types remain raw. Type 26 is vendor-id plus an opaque payload. Named
// Cisco-AVPair decoding is not in this package.
//
// The dictionary declares name, code, value kind, sensitivity, cardinality,
// and packet-role legality. Message-Authenticator is allowed on
// Accounting-Request (validate-if-present is crypto/server) and required as
// the first attribute on Access and Accounting responses. HMAC validation
// and User-Password hiding live in package crypto.
//
// This package must not import the RADIUS codec, crypto, server, UDP, TACACS,
// config, state, AAA, API adapters, HTTP, events, or observability.
package attribute

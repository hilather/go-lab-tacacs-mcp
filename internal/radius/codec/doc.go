// Package codec encodes and decodes RADIUS packets.
//
// It does not perform network I/O, hide User-Password, or compute
// authenticators. One datagram is decoded at a time; declared length is
// 20..4096 for both access and accounting. Trailing bytes past the declared
// length are padding and ignored. Access-Challenge (11) is decoded so a
// later adapter can discard it; it is not an advertised feature.
//
// This package must not import config, state, AAA, API adapters, TACACS,
// HTTP, events, or observability.
package codec

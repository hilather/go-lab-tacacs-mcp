// Package tls is the RADIUS/TLS 1.3 (RadSec) stream listener.
//
// It is a stream of length-prefixed RADIUS packets (RFC 6613 §2.6) inside
// TLS 1.3 (RFC 6614). It is not a TLS wrap of the UDP datagram handler.
// This package must not import internal/radius/udp or internal/tacacs/tls.
package tls

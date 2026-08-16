// Package tls is an independent RadSec (RADIUS/TLS) client.
//
// It must not import production RADIUS codec, crypto, server, or udp
// packages. Framing is RFC 6613 length-prefixed RADIUS packets inside TLS 1.3.
package tls

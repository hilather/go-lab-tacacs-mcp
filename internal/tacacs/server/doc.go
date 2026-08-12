// Package server multiplexes TACACS+ sessions after a transport adapter
// binds client identity. It owns single-connect negotiation, sequence
// checks, limits, and dispatch to a protocol-independent Handler.
//
// Packet I/O (obfuscation, TLS record framing) stays in the transport
// adapter. This package must not import the independent test client.
package server

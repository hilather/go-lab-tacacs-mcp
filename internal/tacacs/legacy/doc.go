// Package legacy binds the RFC 8907 TACACS+ TCP listener.
//
// It matches the TCP peer against the compiled snapshot, binds the
// client's shared secret for the connection lifetime, applies
// obfuscation, and rejects cleartext bodies. Session multiplexing lives
// in package server.
package legacy

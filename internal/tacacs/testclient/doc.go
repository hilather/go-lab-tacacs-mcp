// Package testclient is an independent TACACS+ test client.
//
// Encoding uses the copy under testclient/codec only. This package must
// not import the server codec or internal/tacacs/tls. RFC 9887 client-role
// behavior lives here (DialTLS): immediate TLS 1.3, DNS-ID/IP-ID/SRV-ID
// (never URI-ID), UNENCRYPTED on every packet, no 0-RTT, no legacy fallback.
package testclient

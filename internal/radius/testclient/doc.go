// Package testclient is an independent RADIUS test client.
//
// Encoding uses the copy under testclient/codec only. This package must
// not import production internal/radius/codec, crypto, attribute, server,
// or udp. Shared-codec loopback is not conformance evidence.
//
// This package does not advertise complete RADIUS. UDP exchange helpers
// come after a production listener exists.
package testclient

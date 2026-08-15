// Package codec is the independent RADIUS packet, attribute, and
// authenticator copy used only by the test client.
//
// It must not import production internal/radius/codec, crypto, attribute,
// server, or udp. Wire behavior is proven against testdata/protocol/radius
// fixtures and by comparing encoded bytes with the production codec from
// production tests. Shared types are not evidence.
//
// MD5 and HMAC-MD5 exist only because RADIUS/UDP requires them.
package codec

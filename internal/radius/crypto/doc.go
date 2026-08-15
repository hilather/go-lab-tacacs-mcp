// Package crypto implements RADIUS authenticators, User-Password hiding,
// and Message-Authenticator.
//
// MD5 and HMAC-MD5 are used only because RADIUS/UDP requires them
// (RFC 2865, RFC 2866, RFC 2869, RFC 3579; ADR 0016). This is not a
// general-purpose digest package. Do not add helpers here for other
// protocols.
//
// Access-Request Authenticator is a 16-byte nonce. The server must not
// treat it as a MAC. Accounting-Request Authenticator and every
// Response Authenticator are MD5 checksums. Message-Authenticator is
// HMAC-MD5 over the declared packet with the attribute value zeroed.
//
// These are primitives only. They do not implement require-versus-allow
// Message-Authenticator policy, insert Message-Authenticator first on
// responses, or serve UDP.
//
// This package may import codec and attribute. It must not import aaa,
// API adapters, TACACS, config, or state. Secrets and unhidden
// passwords never appear in errors or fmt output of this package's types.
package crypto

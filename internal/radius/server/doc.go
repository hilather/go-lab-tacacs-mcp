// Package server translates RADIUS packets to AAA operations.
//
// The current handler is a structural stub: after a successful decode it
// emits Access-Reject or Accounting-Response with Message-Authenticator
// first, then the Response Authenticator. It is not a PAP/CHAP path and
// does not record accounting. Full integrity and authentication are later.
//
// This package may import the RADIUS codec, attributes, and crypto. It
// must not import TACACS, policy evaluation, or API adapters.
package server

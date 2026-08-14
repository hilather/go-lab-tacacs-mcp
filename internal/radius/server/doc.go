// Package server translates RADIUS packets to AAA operations.
//
// Access-Request runs the endpoint MA / limit_proxy_state algorithm, extracts
// PAP or CHAP evidence, and calls aaa.AuthenticateAccess. Unknown user, bad
// password, CHAP length, conflicting methods, and default-deny are
// Access-Reject. There is no Access-Accept until policy evaluation.
// Accounting-Request is still a structural stub (validate request
// authenticator, Accounting-Response).
//
// This package may import AAA, the RADIUS codec, attributes, and crypto. It
// must not import TACACS, policy evaluation, or API adapters.
package server

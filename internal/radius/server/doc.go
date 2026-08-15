// Package server translates RADIUS packets to AAA operations.
//
// Access-Request runs the endpoint MA / limit_proxy_state algorithm, extracts
// PAP or CHAP evidence, and calls aaa.AuthenticateAccess. Permit is
// Access-Accept with legal profile attributes (Message-Authenticator first,
// then Proxy-State). Unknown user, bad password, CHAP length, conflicting
// methods, policy deny, default deny, and evaluator errors are Access-Reject.
//
// Accounting-Request is validated (Request Authenticator, inbound
// Message-Authenticator if present), mapped onto the five MVP status
// types, and recorded through aaa.RecordRADIUSAccounting. Accounting-
// Response always inserts Message-Authenticator first.
//
// This package may import AAA, the RADIUS codec, attributes, and crypto. It
// must not import TACACS, policy evaluation, or API adapters.
package server

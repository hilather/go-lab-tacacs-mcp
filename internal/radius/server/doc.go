// Package server translates RADIUS packets to AAA operations.
//
// Access-Request runs the endpoint MA / limit_proxy_state algorithm, extracts
// PAP, CHAP, or EAP Identity/MD5 evidence, and calls aaa.AuthenticateAccess.
// Permit is Access-Accept with legal profile attributes (Message-Authenticator
// first, then Proxy-State). EAP Identity/MD5 may emit Access-Challenge with
// State. Unknown user, bad password, CHAP length, conflicting methods, policy
// deny, default deny, evaluator errors, unimplemented EAP types, and
// Challenge-State gate failures are Access-Reject.
//
// Accounting-Request is validated (Request Authenticator, inbound
// Message-Authenticator if present), mapped onto the five MVP status
// types, and recorded through aaa.RecordRADIUSAccounting. Accounting-
// Response always inserts Message-Authenticator first.
//
// This package may import AAA, the RADIUS codec, attributes, and crypto. It
// must not import TACACS, policy evaluation, or API adapters.
package server

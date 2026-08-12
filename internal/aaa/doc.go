// Package aaa is the protocol-independent AAA service.
//
// Authentication covers ASCII LOGIN, PAP, CHAP, MS-CHAP v1/v2, ENABLE
// (authen_type ignored), and ASCII CHPASS. Authorization uses the two
// policy evaluators. Accounting START (and other valid flag combinations)
// is accepted into the event ring.
//
// Authorize and ExplainAuthorization share Evaluate so live AUTHOR packets
// and policy.evaluate produce the same decision for the same snapshot.
//
// TACACS packet types do not appear here. Listeners translate.
package aaa

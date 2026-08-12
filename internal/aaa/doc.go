// Package aaa is the protocol-independent AAA service.
//
// Authentication covers ASCII LOGIN, PAP, CHAP, MS-CHAP v1/v2, ENABLE
// (authen_type ignored), and ASCII CHPASS. Authorization uses the two
// policy evaluators. The full RFC 8907 accounting flag table (START, STOP,
// WATCHDOG, WATCHDOG+update) is accepted; SUCCESS is returned only after
// the event ring accepts the record.
//
// Authorize and ExplainAuthorization share Evaluate so live AUTHOR packets
// and policy.evaluate produce the same decision for the same snapshot.
//
// TACACS packet types do not appear here. Listeners translate.
package aaa

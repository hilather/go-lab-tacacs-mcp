// Package aaa is the protocol-independent AAA service.
//
// This skeleton implements ASCII LOGIN, session/service and command
// authorization through the two policy evaluators, and accounting START
// (plus other valid flag combinations) accepted into the event ring.
// Remaining authentication flows return ERROR until later work.
//
// TACACS packet types do not appear here. Listeners translate.
package aaa

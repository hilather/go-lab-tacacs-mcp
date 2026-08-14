// Package radius will compile and evaluate RADIUS access policy.
//
// It must not import AAA, the TACACS policy parent, RADIUS packet or
// socket packages, TACACS, or API adapters. Shared enums live in domain.
// Attribute types may be imported later.
package radius

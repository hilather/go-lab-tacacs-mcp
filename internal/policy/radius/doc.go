// Package radius compiles and evaluates RADIUS access policy.
//
// Walk: user radius_policy_id, then each effectiveGroups policy,
// then client endpoint access_policy_id, then optional
// fallback_radius_policy_id, then default deny. AuthMethod and
// Effect live in domain.
//
// This package must not import AAA, the TACACS policy parent, RADIUS
// packet/socket packages, TACACS, API adapters, or YAML syntax types.
// Normalized config objects are the compile input.
package radius

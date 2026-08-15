// Package radius compiles and evaluates RADIUS access policy.
//
// MVP walk: client endpoint access_policy_id, then optional
// fallback_radius_policy_id, then default deny. User/group RADIUS
// rules are not compiled. AuthMethod and Effect live in domain.
//
// This package must not import AAA, the TACACS policy parent, RADIUS
// packet/socket packages, TACACS, API adapters, or YAML syntax types.
// Normalized config objects are the compile input.
package radius

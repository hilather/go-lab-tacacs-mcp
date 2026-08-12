// Package credentials holds typed secret material that refuses JSON, text,
// and fmt serialization of raw values.
//
// Distinct holder types prevent cross-purpose assignment (login verifier vs
// challenge secret vs ENABLE vs shared secret vs token vs TLS material).
package credentials

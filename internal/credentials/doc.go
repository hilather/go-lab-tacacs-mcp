// Package credentials holds typed secret material and verifies it.
//
// Distinct holder types prevent cross-purpose assignment (login verifier vs
// challenge secret vs ENABLE vs shared secret vs token vs TLS material).
// ASCII/PAP and ENABLE use Argon2id PHC strings. CHAP/MS-CHAP use a separate
// clear-equivalent challenge secret. Token helpers store only a SHA-256 digest.
//
// fmt redacts a holder printed directly or as an exported field. Unexported
// fields are walked by reflect without calling Format, so %+v / %#v dump the
// backing bytes as decimals or hex. Keep holders in exported fields, or log
// via slog or Redacted(); do not log %+v of internal request structs.
//
// This package must not import net, HTTP, config, state, TACACS, or API
// adapters. Parameters for new verifiers are recorded in
// docs/decisions/0002-password-kdf.md.
package credentials

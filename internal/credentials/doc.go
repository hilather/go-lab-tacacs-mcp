// Package credentials holds typed secret material that refuses JSON, text,
// and fmt serialization of raw values.
//
// Distinct holder types prevent cross-purpose assignment (login verifier vs
// challenge secret vs ENABLE vs shared secret vs token vs TLS material).
//
// fmt redacts a holder printed directly or as an exported field. Unexported
// fields are walked by reflect without calling Format, so %+v / %#v dump the
// backing bytes as decimals or hex. Keep holders in exported fields, or log
// via slog or Redacted(); do not log %+v of internal request structs.
package credentials

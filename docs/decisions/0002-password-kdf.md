# ADR 0002: Password KDF, Username Profile, and MS-CHAP Canonicalization

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P5.1  
Related conformance rows: T89-H-012, T89-TYPE-003–005, T89-FLOW-004–006, T89-FLOW-012

## Context

ASCII/PAP cannot share a credential representation with CHAP or MS-CHAP. A one-way login verifier cannot compute a challenge response. ENABLE must stay distinct from both. RFC 8907 requires UsernameCasePreserved, not a lowercase fold. MS-CHAP v2 ChallengeHash includes a username octet string that must match the identifier used for user lookup.

The implementation needs a recorded Argon2id parameter set, a PHC encoding, an MS-CHAP username rule, and a place for KDF cost that does not pollute ordinary policy-engine latency budgets.

## Decision

1. **ASCII/PAP and ENABLE** use Argon2id via `golang.org/x/crypto/argon2`. Stored material is a PHC string:

   ```text
   $argon2id$v=19$m=<KiB>,t=<iter>,p=<lanes>$<b64salt>$<b64hash>
   ```

   Salt and digest use standard Base64 without padding.

2. **Encode-time parameters** for new lab verifiers (runtime password create/change):

   | Parameter | Value | Rationale |
   |---|---:|---|
   | Algorithm | Argon2id | Hybrid side-channel / GPU resistance (RFC 9106) |
   | Version | 19 | Current Argon2 version |
   | Memory | 65536 KiB (64 MiB) | RFC 9106 second recommended memory |
   | Time | 3 | RFC 9106 second recommended iterations |
   | Parallelism | 1 | One hash stays near 64 MiB on a single-replica lab process (RFC 9106 second option uses p=4) |
   | Salt | 16 bytes from `crypto/rand` | |
   | Output | 32 bytes | |

   These constants live in `credentials.DefaultParams`.

3. **Verify-time parameters** come from the stored PHC string. Imported argon2id v=19 hashes with `8 ≤ m ≤ 1048576` KiB, `1 ≤ t ≤ 16`, `1 ≤ p ≤ 16`, salt ≥ 8 bytes, tag ≥ 16 bytes are accepted. argon2i, argon2d, other versions, and plaintext are rejected.

4. **Test-only parameters** (`credentials.TestParams`, m=8 KiB, t=1, p=1) may be injected by unit tests. They must not be the production encode default.

5. **Usernames** are RFC 8265 UsernameCasePreserved via `golang.org/x/text/secure/precis`. The canonical output is the TACACS user `id` and the MS-CHAP v2 `UserName` octet string (UTF-8 of that output). No extra domain strip and no case fold.

6. **CHAP** is MD5(`PPP_id || secret || challenge`) (RFC 1994 / RFC 8907 §5.4.2.3). Minimum challenge length defaults to 8 octets.

7. **MS-CHAP v1 / v2** follow RFC 2433 / RFC 2759. The TACACS START field is `PPP_id(1) || challenge || response`. The PPP identifier is **not** mixed into the MS-CHAP DES/SHA-1 calculation. Challenge secret absence does not fall back to the login verifier.

8. **Password change** writes a new Argon2id PHC for overlay publication only. It never derives a challenge secret and never edits the baseline file.

9. **API tokens** are ≥256 bits from `crypto/rand`. Only SHA-256(token) is retained. Compare digests in constant time.

10. **KDF cost** is benchmarked under `internal/credentials` (`BenchmarkArgon2idVerify`, `BenchmarkArgon2idVerifyParallel`) and is excluded from `make bench` (`internal/tacacs`, `internal/policy`, `internal/state`). Concurrent Argon2 is gated by a worker semaphore (default 2).

## Alternatives considered

### bcrypt

Available and simple, but weaker against GPU guessing at comparable latency and not the design default.

### RFC 9106 first recommended (2 GiB, t=1, p=4)

Too large for a laptop lab appliance.

### RFC 9106 second recommended with p=4

Honors the RFC lane count but peaks near 256 MiB per hash. p=1 keeps the 64 MiB memory target on one process. Stored PHC still records `p`, so a future encode bump is possible.

### Lowercasing usernames

Rejected. RFC 8907 requires UsernameCasePreserved.

### Using the login Argon2id verifier for CHAP

Impossible without a preimage. Challenge methods keep a separate clear-equivalent secret.

## Consequences

### Positive

- Slow verifiers and challenge secrets cannot be assigned to each other.
- PHC strings are portable and self-describing.
- MS-CHAP v2 username matches lookup, so PRECIS and RFC 2759 do not diverge.
- Ordinary benches stay fast.

### Negative

- New hashes take tens to hundreds of milliseconds and ~64 MiB.
- p=1 is weaker against some parallel attacks than p=4 at the same memory.
- Challenge secrets remain reversible in process memory.

### Mitigations

- Bound concurrent KDF workers.
- Dummy Argon2/CHAP work on unknown users so failure cost stays comparable.
- Canary tests forbid secrets in errors and JSON.
- Wipe ephemeral password copies after hashing.

## Compatibility impact

- Secret files for `login.verifier` and `enable.verifier` must be argon2id PHC strings, not plaintext.
- Existing users are keyed by UsernameCasePreserved `id`.
- MS-CHAP v2 clients must send the same username the snapshot stored (case preserved).

## Migration

No prior verifier format exists in this repository. If parameters change later, keep verify-from-PHC and encode new hashes with the new default. Do not silently rehash on login.

## Test impact

- Independent CHAP MD5 vectors that differ only by PPP id.
- RFC 2759 appendix MS-CHAP v2 vector plus RFC 3079 NT-hash check for v1.
- Correct / wrong / missing / disabled / expired / restricted records.
- ENABLE and CHAP refuse login-only material.
- Password change leaves challenge secrets unchanged.
- Secret canaries on verify errors and token digests.
- Race coverage on concurrent ASCII and CHAP verify.
- Separate KDF benches under `internal/credentials`.

## Documentation impact

`docs/decisions/0002-password-kdf.md` is the parameter SoT. `docs/TESTING_AND_BENCHMARKS.md` §8.4, `docs/REFERENCES.md`, `docs/TASKS.md` P5.1, and the root README link here.

## Revisit conditions

- Reference hardware cannot meet the 64 MiB / t=3 encode cost.
- OWASP or RFC 9106 recommendations change materially.
- A second username profile is required for a specific NAS.
- Token digest must become a keyed MAC (process-local HMAC) instead of SHA-256.

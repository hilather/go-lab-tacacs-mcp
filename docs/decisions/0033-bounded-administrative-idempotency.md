# ADR 0033: Bounded administrative idempotency

Status: Accepted
Date: 2026-10-03
Related task: P9.2

## Context

REST and MCP accepted replay keys without enforcing their documented semantics.
Retries with an original revision could fail after the first mutation succeeded.
Token creation also returns a bearer value exactly once, which forbids caching it.

## Decision

The common operation registry supports replay keys for users.create, groups.create,
clients.create, runtime.reset and config.reload. Other operations reject nonempty
keys before effects, including tokens.create as an EXEMPT_BY_ADR exception to the
general create replay rule. Both adapters retain equivalent token creation behavior.

Keys are opaque byte sequences limited to 256 bytes. Identity hashing encodes key bytes injectively, preserving distinct HTTP header values even when they are not valid UTF-8. REST passes the parsed `Idempotency-Key` field value to the registry unchanged. HTTP field parsing removes leading and trailing SP/HTAB (optional whitespace, RFC 9110 §5.5), so those characters on the wire are not part of the key; every other byte, including Unicode whitespace such as U+00A0, is significant. An empty field value is the same as no key. MCP `idempotency_key` strings are used exactly as given. The store admits at most 128 entries and reserves
64 KiB per entry within an 8 MiB payload budget; fixed entry metadata is additional
bounded overhead. Pending entries count against capacity and never expire or get
evicted. Completed entries expire ten minutes after completion. Full capacity
returns unavailable before running a handler. Restart discards all entries. Runtime reset and reload preserve entries until TTL; this bounded bookkeeping is separate from the overlay.

Authorization runs before lookup. Identity, current token generation and sorted
current scopes isolate keys. Session cookies and bearer access to the same token
incarnation share entries. A keyed HMAC fingerprints operation, typed input and
original expected revision; request bodies and secrets are never retained.
Changing any fingerprint input returns conflict. Successful responses are stored
as JSON and decoded into their original type for each retry, preserving revision
and preventing callers from mutating stored data. The supported response types
are secret-free User, Group, Client, ReloadConfigResult and ResetRuntimeResult.

Concurrent identical requests wait for the first invocation; canceling a waiter
cancels only its wait. Failed executions retain only their domain error code and
return a generic safe error on replay. Non-domain failures replay unavailable.
A successful response too large to cache is delivered to its owner and leaves an
unavailable tombstone. Retries never repeat those effects during the TTL. Check
state before retrying with a new key. Error details and messages are not cached.

## Alternatives and consequences

Unbounded caching and eviction of live entries permit denial of service or repeat
side effects. Persistent replay would violate the ephemeral process model. Token
bearer replay would violate one-time disclosure. Admission rejection and explicit
unsupported keys make these limits visible. Expiry permits a key to execute again;
clients must not rely on permanent exactly-once guarantees.

## Compatibility and migration

Existing unkeyed calls retain their behavior. Keyed retries now replay successes;
unsupported keyed operations return invalid_argument. Clients must preserve the
original payload and revision and use keys only on the documented operations.

## Test and documentation impact

Regression, authorization, conflict, capacity, expiry, concurrency and adapter
parity tests cover the common registry. API schemas describe supported operations
and bounds; operator contracts and P9.2 evidence record the replay policy.

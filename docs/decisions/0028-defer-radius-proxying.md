# ADR 0028: Defer RADIUS Proxying and Realm Routing

Status: Accepted  
Date: 2026-08-16  
Decision owners: TacLab maintainers  
Related tasks: RAD-EXT-008  
Related conformance rows: R65-PROXY-001, PRJ-SEC-002  
Source design: [docs/designs/radius-remaining-work.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/designs/radius-remaining-work.md)

## Context

A lab appliance with fail-closed unknown-client discard, a single replica, and memory-only state is a **terminator**, not a relay. RADIUS proxying requires a second secret domain, loop detection / hop count, Proxy-State mutation, realm routing and strip, failure/timeout mapping that is not silent discard, and amplification controls on the outbound hop.

Shipped TacLab already preserves Proxy-State order on responses (`R65-PROXY-001`). That is not proxying.

EAP pass-through to an external EAP server is the same second hop.

## Decision

1. RADIUS proxying / realm routing stays **out**. `RAD-EXT-008` is `DEFERRED_MAY` under this ADR.
2. No static next-hop. No realm strip. No open relay. No EAP pass-through.
3. No `proxy` YAML key. Unknown `proxy:` in v2 is `CONFIG_UNKNOWN_FIELD`.
4. Existing Proxy-State echo-on-response behavior is unchanged.

## Alternatives considered

### Bounded static RADIUS proxy (one named next-hop)

Deferred, not built. Safer than an open relay but still a second product (timeouts, hop-count, secret domains). See Revisit.

### Implement proxying in the same remaining-work DAG

Rejected. Open-relay risk conflicts with unknown-client discard and the single-replica memory model.

## Consequences

### Positive

- TacLab cannot become an accidental open relay.
- Scope stays a lab terminator.

### Negative

- TacLab cannot forward Access-Request to an external IdP.
- EAP pass-through stays out (ADR 0022).

## Compatibility impact

None. No proxy configuration exists today. This ADR forbids adding it without a new decision that satisfies Revisit.

## Migration

None. Operators who need a relay use a dedicated proxy, not TacLab.

## Test impact

- When v2 validation is extended in a later PR that might see `proxy:`, unknown-field reject is required.
- Do not add proxy next-hop tests as if the feature were in scope.

## Documentation impact

[docs/RADIUS_CONFORMANCE.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/RADIUS_CONFORMANCE.md) §8 and [docs/TASKS.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/TASKS.md) §22.4 record `RAD-EXT-008` as `DEFERRED_MAY`.

## Revisit conditions

An operator needs TacLab to forward Access-Request to an external IdP **and** accepts a bounded static next-hop design (one hop, named realm, no wildcard, no open relay). That requires a new ADR covering secrets, hop-count, Proxy-State mutation, timeout mapping, and amplification.

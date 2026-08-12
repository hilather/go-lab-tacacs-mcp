# ADR 0001: All-in-One Go Service with Distinct Legacy and Secure TACACS+ Listeners

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P8.1, P8.3, P8.4, P8.6, P14  
Related conformance rows: T98-TLS-001 through T98-TLS-015, T98-ROLE-006

## Context

TacLab is a reproducible lab appliance, not a general-purpose production identity platform. The selected product architecture is one Go process containing the TACACS+ protocol service, shared application operations, REST API, MCP server, and embedded React/TypeScript UI.

The lab must reproduce both:

- legacy TACACS+ behavior protected by a per-client shared secret; and
- secure TACACS+ over TLS 1.3 with mutual certificate authentication.

The secure TACACS+ specification recommends separating secure and legacy services to reduce downgrade and cross-protocol risk. A one-process lab deployment is operationally simpler, but it must not turn that convenience into one ambiguous listener, automatic fallback, protocol sniffing, or credential reuse.

## Decision

TacLab will support both transports in one Go process for lab use, subject to the following mandatory boundaries.

1. Legacy and secure TACACS+ use separate listener objects, separate sockets, and distinct configured ports.
2. The reference container listens on unprivileged internal ports and maps host TCP port 49 to legacy TACACS+ and host TCP port 300 to secure TACACS+.
3. The secure listener begins TLS immediately. It never accepts a plaintext TACACS packet, an in-band upgrade request, or a protocol-discovery preface.
4. The legacy listener never accepts a TLS ClientHello as a route to the secure service.
5. Failure on the secure listener never triggers an automatic retry or fallback to the legacy listener.
6. Legacy shared secrets, TLS private keys, certificate trust material, and any future external TLS PSKs use distinct typed configuration and secret holders. A value must not be silently reused across those purposes.
7. TACACS+ packet processing after transport establishment shares the same bounded codec and session machinery, but transport-specific flag, obfuscation, identity, and closure rules remain explicit adapters.
8. The default reference lab may enable both listeners. A TLS-only profile must be supported and presented as the preferred mode for new or production-like security testing.
9. Startup/status/UI output must identify the deployment as a co-located lab topology when both listeners are enabled and display a non-secret security warning.
10. This decision does not authorize running both protocols on one port or advertising the topology as a production best practice.

## Architecture consequences

### Positive

- One image and one Compose service reproduce the full compatibility matrix.
- REST, MCP, UI, configuration, events, and metrics share one effective state revision.
- Runtime-created users and policies are immediately consistent across both transports.
- The lab is easier to start, reset, export, and tear down.
- Common packet and policy code can be tested once while preserving transport-specific rules at the listener boundary.

### Negative

- Compromise of the one process affects both transports and the management plane.
- Operators can accidentally expose legacy TACACS+ beside the secure service unless configuration and UI warnings are clear.
- Resource exhaustion on one listener can affect the process unless quotas and fair scheduling are enforced.
- This topology is not the preferred production-security topology.

### Mitigations

- Separate listener configuration, connection limits, metrics, and error codes by transport.
- Require explicit enablement for each listener.
- Keep packet-body obfuscation confined to the legacy adapter.
- Require TLS 1.3, immediate handshake, and no early data on the secure adapter.
- Never provide cross-listener fallback.
- Use typed secrets and canary tests to prevent value reuse or leakage.
- Permit TLS-only configuration and document separate-host/separate-instance deployment for production-like evaluation.
- Run the container non-root with a read-only root filesystem, dropped capabilities, bounded resources, and management-network restrictions.

## Alternatives considered

### Separate processes or containers by default

This provides stronger fault and credential isolation, but complicates the initial lab workflow and creates synchronization problems for the intentionally in-memory runtime overlay. It remains a valid production-like deployment pattern and may be added through separate instances of the same image.

### A Go management plane with an external TACACS daemon

This could inherit protocol maturity from another implementation, but would split state and policy, complicate runtime mutation, and undermine the selected all-in-one option. It remains a fallback only if conformance testing proves an in-process implementation cannot meet release requirements.

### One port with protocol sniffing or negotiated upgrade

Rejected. It conflicts with immediate TLS, increases downgrade and cross-protocol risk, and makes client behavior ambiguous.

### Automatic secure-to-legacy fallback

Rejected. A failed secure connection must remain a failed secure connection.

## Compatibility impact

- Existing legacy clients continue to target port 49 or an explicit legacy override.
- Secure TACACS+ clients target port 300 or an explicit secure override.
- Clients must be configured for one transport endpoint; no server-side transparent migration occurs.
- TLS-only deployments can disable the legacy listener without changing users, groups, or policy semantics.

## Configuration impact

The schema must maintain independent `listeners.legacy_tacacs` and `listeners.secure_tacacs` sections. Client definitions must declare allowed transports. Legacy secret references are valid only for legacy matching; certificate identities and future TLS authentication material are valid only for secure matching.

Validation must reject:

- identical bind addresses/ports for enabled legacy and secure listeners;
- a secure listener without required TLS configuration;
- implicit fallback configuration;
- cross-purpose secret assignment; and
- ambiguous client matching after transport selection.

## Test impact

Release evidence must include:

- plaintext TACACS sent to the TLS port is rejected;
- TLS ClientHello sent to the legacy port is rejected;
- no successful request occurs before the TLS handshake completes;
- TLS failure does not produce a legacy connection attempt;
- packet obfuscation occurs only on legacy transport;
- the RFC-required TLS packet flag state is enforced only in the secure adapter;
- separate per-listener connection and saturation tests;
- secret-canary tests proving no shared value crosses secret types;
- a TLS-only Compose profile; and
- a co-located-lab warning in status, UI, and operator documentation.

Every discovered transport-boundary defect becomes a permanent regression fixture.

## Performance impact

The process shares CPU and memory between listeners. Benchmarks and sustained-load tests must measure each listener independently and under mixed load. A load on one listener must not create unbounded latency or starvation on the other. Any material change to listener dispatch, TLS handshake handling, or shared connection limits requires updated benchmark evidence.

## Documentation impact

`DESIGN.md`, `ARCHITECTURE.md`, `TACACS_CONFORMANCE.md`, `CONFIGURATION.md`, `LAB_DEPLOYMENT.md`, and operator deployment guidance must preserve the distinction between a convenient co-located lab topology and a preferred TLS-only or separated production-like topology.

## Revisit conditions

Revisit this decision when any of the following occurs:

- runtime state becomes replicated or durable;
- multiple service replicas are supported;
- a production deployment profile is introduced;
- the TACACS specifications materially change transport-separation guidance;
- resource isolation proves insufficient under qualification testing; or
- conformance requires a protocol engine that cannot safely coexist in the same process.

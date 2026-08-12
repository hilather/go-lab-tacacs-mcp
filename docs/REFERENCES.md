# Normative and Implementation References

Status: reference index  
Checked: 2026-08-12  
Codec evaluation: [ADR 0007](decisions/0007-codec-approach.md)  
Specification baseline: RFC 8907, RFC 9887, and MCP 2026-07-28

## 1. How to use this file

Normative protocol behavior comes from the applicable RFC or MCP specification, not from a third-party library, blog post, packet capture, or existing product. Implementation references may guide code structure but cannot override the normative source.

Agents must:

- Record the exact section used for a protocol decision in tests, comments, conformance rows, or an architecture decision record.
- Check RFC errata and current MCP changelogs when upgrading the baseline.
- Pin library and SDK versions in the repository.
- Treat candidate TACACS implementations as interoperability peers or code dependencies, never as the specification.
- Re-run conformance, parity, security, and performance suites after a normative or SDK baseline change.
- Update this file and the `Last updated` date in affected contracts when references change.

## 2. TACACS+ normative baseline

### RFC 8907 - TACACS+

- HTML: https://www.rfc-editor.org/rfc/rfc8907.html
- Information/errata entry: https://www.rfc-editor.org/info/rfc8907
- Published: September 2020
- Status: Informational IETF consensus document
- Updated by: RFC 9887

Use RFC 8907 for:

- Common packet header and versioning.
- Packet-body obfuscation for legacy transport.
- Single Connection Mode.
- Authentication START/CONTINUE/REPLY packets.
- ASCII, PAP, CHAP, MS-CHAP v1, MS-CHAP v2, ENABLE, and ASCII password-change exchanges.
- Authorization REQUEST/RESPONSE and AV-pair behavior.
- Accounting REQUEST/REPLY, START, STOP, and WATCHDOG behavior.
- Sequence numbers, session IDs, flags, statuses, limits, and security considerations.
- Removed, discouraged, and deprecated legacy features.

### RFC 9887 - TACACS+ over TLS 1.3

- HTML: https://www.rfc-editor.org/rfc/rfc9887.html
- Information/errata entry: https://www.rfc-editor.org/info/rfc9887
- Published: December 2025
- Status: Standards Track
- Updates: RFC 8907

Use RFC 9887 for:

- Immediate TLS negotiation on a dedicated listener.
- TLS 1.3 minimum.
- Mutual authentication and the mandatory certificate-based interoperability profile.
- Optional external PSK and raw-public-key dispositions.
- Certificate validation, identity, revocation, cipher, and operational requirements.
- Prohibition of legacy TACACS packet-body obfuscation over TLS.
- Required TACACS unencrypted-flag behavior within TLS.
- TLS resumption and prohibition of early data/0-RTT.
- Downgrade and fallback protections.
- Well-known TCP port 300 (`tacacss`).
- Migration and same-host/separate-host operational guidance.

### Related algorithm and transport RFCs

- TLS 1.3 - RFC 8446: https://www.rfc-editor.org/rfc/rfc8446.html
- Recommendations for Secure Use of TLS and DTLS - RFC 9325 / BCP 195: https://www.rfc-editor.org/rfc/rfc9325.html
- Internet X.509 PKI certificate and CRL profile - RFC 5280: https://www.rfc-editor.org/rfc/rfc5280.html
- Online Certificate Status Protocol - RFC 6960: https://www.rfc-editor.org/rfc/rfc6960.html
- CHAP - RFC 1994: https://www.rfc-editor.org/rfc/rfc1994.html
- Microsoft PPP CHAP Extensions - RFC 2433: https://www.rfc-editor.org/rfc/rfc2433.html
- Microsoft PPP CHAP Extensions, Version 2 - RFC 2759: https://www.rfc-editor.org/rfc/rfc2759.html
- TLS external PSK recommendations - RFC 9257: https://www.rfc-editor.org/rfc/rfc9257.html
- TLS raw public keys - RFC 7250: https://www.rfc-editor.org/rfc/rfc7250.html

The implementation must use vetted cryptographic packages and independent algorithm vectors. Do not copy unreviewed cryptographic code from a TACACS project merely because its wire behavior appears correct.

## 3. MCP normative baseline

### MCP 2026-07-28 specification

- Specification overview: https://modelcontextprotocol.io/specification/2026-07-28
- Base protocol overview: https://modelcontextprotocol.io/specification/2026-07-28/basic
- Versioning: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- Authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- Streamable HTTP: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- Tools: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- Resources: https://modelcontextprotocol.io/specification/2026-07-28/server/resources
- Logging: https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging
- Schema source: https://github.com/modelcontextprotocol/specification

The implementation baseline is explicitly pinned to protocol version `2026-07-28`. Agents must not silently switch behavior to an unpinned `latest` page.

Use the MCP specification for:

- Protocol version negotiation and required request metadata.
- JSON-RPC message handling.
- Stateless request assumptions in the selected revision.
- Streamable HTTP POST endpoint behavior.
- Tool and resource schema rules.
- Authorization behavior for HTTP transports.
- Cancellation, progress, errors, logging, and relevant capability declarations.

### Official Go MCP SDK

- Repository: https://github.com/modelcontextprotocol/go-sdk
- Package documentation: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk
- SDK feature documentation: https://github.com/modelcontextprotocol/go-sdk/tree/main/docs

Pin a released SDK version that explicitly supports MCP `2026-07-28`. Record the version in `go.mod`, status output, SBOM, and release evidence. Review SDK release notes before every upgrade and run the complete parity and MCP transport test suites afterward.

## 4. Go implementation references

### Language and standard library

- Go documentation: https://go.dev/doc/
- Go memory model: https://go.dev/ref/mem
- `net` package: https://pkg.go.dev/net
- `net/http` package: https://pkg.go.dev/net/http
- `crypto/tls` package: https://pkg.go.dev/crypto/tls
- `crypto/x509` package: https://pkg.go.dev/crypto/x509
- `regexp` package: https://pkg.go.dev/regexp
- `sync/atomic` package: https://pkg.go.dev/sync/atomic
- `log/slog` package: https://pkg.go.dev/log/slog
- `testing` package: https://pkg.go.dev/testing

### Current `crypto/tls` capability notes

The implementation spike must check the pinned Go release rather than assuming generic TLS 1.3 support satisfies every RFC 9887 requirement.

- `GetCertificate` and `GetConfigForClient` expose ClientHello/SNI-driven server identity selection.
- `SessionTicketsDisabled`, `SetSessionTicketKeys`, `WrapSession`, and `UnwrapSession` provide resumption controls, but their security properties and wire behavior require dedicated tests.
- `VerifyPeerCertificate` is not called on resumed connections; client-identity and revocation policy that must run on every connection belongs in `VerifyConnection` or resumption must be disabled.
- The Go source currently defines a fixed maximum TLS 1.3 session-ticket lifetime. Arbitrary advertised ticket-lifetime configuration therefore requires an implementation feasibility spike, an isolated alternative, or an approved RFC `SHOULD` disposition; setting a requested value in YAML without enforcing it is prohibited.
- TLS 1.3 cipher suites are intentionally selected by `crypto/tls` rather than through the older `CipherSuites` field. The RFC 9887 cipher-policy `SHOULD` needs an explicit implementation/disposition review.
- RFC 7924 Cached Information Extension support must be verified explicitly. Do not mark it complete from ordinary certificate-chain or session-resumption support.

Relevant public API/source:

- `crypto/tls.Config`: https://pkg.go.dev/crypto/tls#Config
- Go `crypto/tls` source: https://go.dev/src/crypto/tls/common.go

### Security and quality tooling

- Go security resources: https://go.dev/doc/security/
- Go security best practices: https://go.dev/doc/security/best-practices
- Native Go fuzzing: https://go.dev/doc/security/fuzz/
- Fuzzing tutorial: https://go.dev/doc/tutorial/fuzz
- Race detector: https://go.dev/doc/articles/race_detector
- Go vulnerability management: https://go.dev/doc/security/vuln/
- `govulncheck`: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck

A fuzz-discovered input must be retained in the seed corpus so it becomes a normal regression test. Race testing must exercise actual concurrent snapshot publication, single-connect sessions, event readers/writers, and API mutations; merely running `-race` on trivial unit tests is insufficient.

### Password and credential primitives

- Go extended crypto packages: https://pkg.go.dev/golang.org/x/crypto
- Argon2 package: https://pkg.go.dev/golang.org/x/crypto/argon2
- bcrypt package: https://pkg.go.dev/golang.org/x/crypto/bcrypt
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

The selected password verifier algorithm, parameters, upgrade behavior, and benchmark budget are recorded in [ADR 0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md). Challenge-response methods require appropriately protected challenge secret material; a one-way login verifier is not a substitute.

## 5. REST and schema references

- OpenAPI Specification: https://spec.openapis.org/oas/latest.html
- OpenAPI Initiative repository: https://github.com/OAI/OpenAPI-Specification
- JSON Schema: https://json-schema.org/specification
- HTTP Semantics - RFC 9110: https://www.rfc-editor.org/rfc/rfc9110.html
- HTTP/1.1 - RFC 9112: https://www.rfc-editor.org/rfc/rfc9112.html
- Server-Sent Events: https://html.spec.whatwg.org/multipage/server-sent-events.html
- Problem Details for HTTP APIs - RFC 9457: https://www.rfc-editor.org/rfc/rfc9457.html

The REST API may use an RFC 9457-compatible problem shape, but stable TacLab error codes remain the cross-transport contract. HTTP-specific details must not leak into MCP or core operation errors.

## 6. React and TypeScript references

- React documentation: https://react.dev/
- TypeScript documentation: https://www.typescriptlang.org/docs/
- TypeScript configuration reference: https://www.typescriptlang.org/tsconfig/
- Web Content Accessibility Guidelines: https://www.w3.org/TR/WCAG22/
- WAI-ARIA Authoring Practices: https://www.w3.org/WAI/ARIA/apg/
- Content Security Policy Level 3: https://www.w3.org/TR/CSP3/

Frontend dependencies must be selected and pinned during implementation. The UI must use generated REST types, strict TypeScript, accessible components, safe output encoding, and write-only secret inputs.

## 7. Container and deployment references

- Docker multi-stage builds: https://docs.docker.com/build/building/multi-stage/
- Docker build best practices: https://docs.docker.com/build/building/best-practices/
- Docker Compose secrets: https://docs.docker.com/compose/how-tos/use-secrets/
- Compose secrets reference: https://docs.docker.com/reference/compose-file/secrets/
- Compose specification: https://compose-spec.io/
- OCI image specification: https://github.com/opencontainers/image-spec
- OCI runtime specification: https://github.com/opencontainers/runtime-spec
- SPDX specification: https://spdx.dev/specifications/
- SLSA framework: https://slsa.dev/spec/

The reference runtime uses secret files, a multi-stage image, non-root execution, a read-only root filesystem, dropped capabilities, and distinct host port mappings. Deployment documentation must state where source-IP preservation has been verified.

## 8. Candidate TACACS Go implementations

These links are evaluation inputs, not normative authorities:

- Meta Tacquito: https://github.com/facebookincubator/tacquito
- `gotacacs`: https://github.com/vitalvas/gotacacs
- `wxccs/tacacs`: https://github.com/wxccs/tacacs

Before reuse, an agent must evaluate:

- License and dependency licenses.
- Maintenance and release history.
- RFC 8907 coverage by executable test.
- RFC 9887 support or ability to isolate transport from codec.
- Single-connect concurrency and cancellation.
- Parser allocation bounds and malformed-input behavior.
- Race and fuzz results.
- Extensibility through project-owned AAA handlers.
- Independent interoperability.

Any fork or patch set must have an owner, upstream strategy, and regression suite.

Evaluation outcome (2026-08-12): none of the three candidates met the isolation, bounded-parse, RFC-behavior, and pinned-toolchain bar. TacLab 1.0 uses an internal codec. See [ADR 0007](decisions/0007-codec-approach.md).

## 9. Independent interoperability references

Potential independent peers should be selected according to availability, licensing, and lab platform support. Examples may include:

- `tac_plus-ng`: https://projects.pro-bono-publico.de/event-driven-servers/doc/tac_plus-ng.html
- Network operating systems and virtual appliances already used by the lab.
- Packet dissectors capable of decoding TACACS+ when supplied lab credentials.

No release is considered interoperable solely because TacLab's own client and server agree; shared-code defects can make both sides wrong in the same way.

## 10. Reference update procedure

When updating RFC, MCP, SDK, Go, Node, React, OpenAPI, or deployment baselines:

1. Open an ADR or tracked upgrade issue.
2. Record old and new versions/dates.
3. Review normative changelog and errata.
4. Map changed requirements to conformance and operation IDs.
5. Update machine-readable schemas/registries.
6. Add regression tests for changed behavior.
7. Run protocol, parity, security, fuzz-seed, race, frontend, container, interoperability, and benchmark suites.
8. Update every affected design/operator document.
9. Record compatibility and migration impact in release notes.
10. Do not merge with an unresolved mandatory behavior change.

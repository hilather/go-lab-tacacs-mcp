# ADR 0007: Internal TACACS+ Codec as the 1.0 Default

Status: Accepted  
Date: 2026-08-12  
Decision owners: TacLab maintainers  
Related tasks: P1, P3  
Related conformance rows: T89-H-*, T89-FLOW-*, T98-TLS-* (codec/flag isolation)

## Context

TacLab must speak RFC 8907 on the legacy listener and RFC 9887 on a distinct TLS 1.3 listener. Packet types stay inside `internal/tacacs`. AAA, policy, credentials, REST, and MCP must never import a third-party TACACS engine.

The design default is an internal codec with a project-owned encode/decode API. A library may supply **only** encode/decode behind that API, and only if a spike proves:

| Bar | Required property |
|---|---|
| License | Compatible with Apache-2.0; no copyleft or field-of-use restriction in the library or its required transitives |
| RFC 8907 | Header, bodies, sequence, single-connect, printable-ASCII, AV `=`/`*` separators, unknown-type zero-body reply — proven by executable tests, not a README |
| RFC 9887 | Codec isolated from transport; no obfuscation on TLS; `TAC_PLUS_UNENCRYPTED_FLAG` is a transport adapter concern |
| Bounded parse | Read 12 header bytes, then at most `min(header.length, max_packet_body_bytes)` body bytes; truncated or huge `length` must error, never panic or allocate the claimed size |
| Adapter isolation | No policy, credential, YAML, PAM/LDAP, or `net.Conn` types leak through the codec API |
| Toolchain | Compiles with the repository-pinned Go version |
| Independent client | `internal/tacacs/testclient/codec` remains a separate copy and must not import the server codec or the library |

Candidate inputs (not specifications) are listed in `docs/REFERENCES.md`:

- Meta Tacquito: https://github.com/facebookincubator/tacquito
- `gotacacs`: https://github.com/vitalvas/gotacacs
- `wxccs/tacacs`: https://github.com/wxccs/tacacs

Evaluation used those public repositories and source as of 2026-08-12 at the revisions below. README claims were not treated as conformance evidence. These SHAs are audit pins, not `go.mod` dependencies.

| Candidate | Evaluated revision | Tag |
|---|---|---|
| Tacquito | [`77fc9df88b07b1f2c6f750b091d03ac90ca13adc`](https://github.com/facebookincubator/tacquito/commit/77fc9df88b07b1f2c6f750b091d03ac90ca13adc) | none |
| gotacacs | [`0ecbaeeae5e07f66777e14b0d95952752628dd77`](https://github.com/vitalvas/gotacacs/commit/0ecbaeeae5e07f66777e14b0d95952752628dd77) | latest release `v0.4.0` is `d822e3d9dd763ec339b5dd892a87a161d621a351` (not this HEAD) |
| wxccs/tacacs | [`b46f6def055e2f9736586731b064c8aa08d6ff2a`](https://github.com/wxccs/tacacs/commit/b46f6def055e2f9736586731b064c8aa08d6ff2a) | none |

## Decision

TacLab 1.0 implements an **internal codec** in `internal/tacacs/codec`.

1. Do not add Tacquito, gotacacs, or wxccs/tacacs as production dependencies.
2. Production packet types, header/body codecs, and legacy obfuscation are written in-tree against RFC 8907 / RFC 9887.
3. `internal/tacacs/testclient/codec` is a separately owned copy. It must not import `internal/tacacs/codec` or any third-party TACACS package.
4. `tools/spike` holds the evaluation harness and header/obfuscation experiment. It is not the production codec and must not be imported from `internal/`, `cmd/`, or `web/`.
5. A later override requires a new ADR that names the isolated encode/decode surface, the pinned module version, the Go-version impact, and executable rows that close every gap below.

Header encode/decode, unknown-type §3.6 zero-body replies, bounded body allocation, RFC 8907 §4.5 obfuscation, START/CONTINUE/REPLY, author/acct bodies, the version/status matrix, and sequence/single-connect helpers live in `internal/tacacs/codec`. The test client keeps a separate copy under `internal/tacacs/testclient/codec`.

## Candidate evaluation

### Shared observations

All three candidates are MIT-licensed (compatible with Apache-2.0). None met the isolation + RFC-behavior + pinned-toolchain bar as an in-process engine or as a drop-in codec. Tacquito also fails bounded parse; gotacacs I/O is capped (see row).

| Candidate | License | Stated Go | RFC 8907 | RFC 9887 | Isolated codec | Bounded parse | Fuzz / race | Notes |
|---|---|---|---|---|---|---|---|---|
| Tacquito | MIT | 1.26.0 | Claims RFC 8907; server+config+handlers in-tree | TLS 1.3 helper exists; comments still refer to an IETF draft; default client auth is optional | Core packet types sit beside server, secret, and handler APIs | `Packet.UnmarshalBinary` slices `v[12:12+length]` after a max-length check but without checking that the buffer contains `length` bytes | No native `Fuzz*` targets. CI (`push.yml`) runs `go test -v ./...` without `-race`. | Header decode at seq 2 **sets** `SingleConnect`. ASCII check allows control characters. |
| gotacacs | MIT | 1.25 | Header + AAA bodies + single-connect | TLS 1.3 listener helper; unencrypted flag set on TLS | Combined client/server SDK; high-level `Authenticate(user, password)` | Header type stores uncapped `Length`. Client `recvPacket` and server `readRawPacket` reject `Length > maxBodyLength` (default 256KiB) before `make`. That is a cap, not TacLab’s `min(length, max_packet_body_bytes)` (65536). Does **not** fail the bounded-parse bar. | Native `Fuzz*` on header, packet bodies, and obfuscation. CI runs `go test -race ./...`; no fuzz-smoke job. | `ArgValues` splits only on `=`, dropping `*` mandatory AV pairs. Unknown type is a decode error, so it cannot produce the RFC 8907 §3.6 identical-header, seq+1, length-0 reply. |
| wxccs/tacacs | MIT | 1.26.4 | Separate `packet/` package; `ErrorHeader` matches §3.6 shape | TLS 1.3 transport package; README claims RFC 9887 | `packet/` is closer to a codec, but the module also ships YANG, PAM, LDAP, CLI, and Prometheus | Header decode is 12-byte bounded; `Validate` rejects undefined flag bits | Native `Fuzz*` in `packet/`, `crypto/`, `transport/`, `types/`, `legacy/`. CI runs `go test -race` and `make fuzz FUZZTIME=15s`. | 0 stars / 38 commits at evaluation; README completeness is not evidence. Flag-bit reject conflicts with “ignore unknown flags on read”. |

### Tacquito (`github.com/facebookincubator/tacquito`)

Tacquito is the most mature of the three (public RFC 8907 server, injected handlers, prefix/DNS secret providers). It is still the wrong 1.0 engine:

- The useful unit is a **server framework**, not an encode/decode API. Config, bcrypt authenticators, “stringy” authorizers, and secret providers live in the same project. Using it as the in-process engine would import a second policy and credential model.
- `go.mod` requires **Go 1.26.0**. TacLab is pinned to **Go 1.24.5**.
- `Packet.UnmarshalBinary` can panic on a truncated buffer whose header `length` is ≤ 65536 but larger than the remaining bytes.
- `Header.UnmarshalBinary` forces the single-connect flag on sequence 2 instead of negotiating only the first request/reply pair and ignoring the flag afterward.
- Printable-field checks use `unicode.MaxASCII` and do not reject control characters (RFC 8907 §3.7).
- TLS helpers require TLS 1.3 but default `ClientAuth` to `VerifyClientCertIfGiven`. TacLab’s baseline is `RequireAndVerifyClientCert` on a dedicated listener, with obfuscation and flag policy in adapters — not in the codec.
- `SetPacketBodyUnsafe` is documented as test-only and panics on marshal errors. Do not copy that helper. The on-path bounded-parse defect is `Packet.UnmarshalBinary`, above.

A hypothetical override would need a maintained, version-pinned **packet-only** subset (or a fork with an owner), a Go-version ADR, a panic-free bounded reader, flag/seq behavior aligned to RFC 8907, and no handler/config types on the TacLab side of the adapter.

### gotacacs (`github.com/vitalvas/gotacacs`)

gotacacs is a compact MIT client/server SDK that names RFC 8907 and RFC 9887.

- `go.mod` requires **Go 1.25**, newer than the pinned toolchain.
- `Header.Validate` rejects unknown packet types. TacLab must still decode the 12-byte header and reply with the identical cleartext header, sequence + 1, length 0 (RFC 8907 §3.6).
- AV helpers keep only `key=value` and ignore `key*value`. Authorization/accounting conformance requires preserving both separators and duplicates.
- The public API is a **session SDK** (`NewClient`, `NewServer`, `HandleAuthenStart`) that takes passwords and returns policy-shaped replies. That is not an isolated codec.
- Header unmarshal records `Length` without a cap. Transport I/O already rejects `header.Length > maxBodyLength` (default 256KiB) before allocating the body. That is bounded, but it is not TacLab’s `min(length, max_packet_body_bytes)` policy (recommended 65536).

An override would require extracting header/body marshalers, changing unknown-type and AV-separator behavior, aligning the I/O cap with TacLab’s body budget if the codec is reused, and wrapping the result so AAA never sees gotacacs types.

### wxccs/tacacs (`github.com/wxccs/tacacs`)

wxccs/tacacs has the cleanest package split (`packet/`, `crypto/`, `transport/`) and an `ErrorHeader` helper that matches the unknown-type reply shape.

- `go.mod` requires **Go 1.26.4** and pulls PAM, LDAP, Cobra, Viper, Logrus, and Prometheus into the same module.
- `Header.Validate` rejects undefined flag bits. TacLab ignores unknown flags on read and zeros them on write.
- Public history at evaluation was short (tens of commits, no stars or releases). Completeness claims in the README are not executable TacLab evidence.
- The module also implements original TACACS (RFC 1492) and a YANG/RFC 9950 config model. Those are out of TacLab 1.0 scope and increase the review surface.

An override would require depending only on a versioned `packet`+obfuscation subset that compiles on the pinned Go release, ignoring unknown flags on read, and re-running the full TacLab golden/fuzz suite. That is more work than writing the internal codec against the RFCs, and it would still need a separate testclient copy.

## Architecture consequences

### Positive

- Wire behavior is owned by TacLab tests and the RFC citations in those tests.
- Codec, legacy obfuscation, and TLS flag policy stay in separate packages as required by ADR 0001.
- No third-party AAA/policy/credential types enter `internal/aaa` or `internal/policy`.
- The pinned Go 1.24.5 toolchain is unchanged.
- The independent test client can be a mechanical copy of the internal codec without importing a shared library.

### Negative

- Header, body families, sequence machines, and obfuscation must be implemented and fuzzed in-tree.
- Interop bugs found against Tacquito/gotacacs/wxccs/tac_plus-ng are TacLab bugs to fix, not upstream tickets we can wait on.

### Mitigations

- Keep `tools/spike` as archived evidence of the header layout and MD5 pad; do not grow it into a second codec.
- Land production header + pad, then packet families, behind golden fixtures in `testdata/protocol` and native Go fuzz seeds.
- Treat candidate libraries as **interop peers**, not specifications.
- Do not copy unreviewed cryptographic routines from those trees. Challenge-response algorithms use vetted packages and independent RFC vectors.

## Alternatives considered

### Adopt Tacquito as the in-process engine

Rejected. It couples transport to a foreign handler/config/policy stack, requires Go 1.26, and has bounded-parse and flag-handling defects relative to TacLab’s conformance rows.

### Adopt gotacacs or wxccs `packet` as the codec behind a thin adapter

Rejected for 1.0. Both need a newer Go toolchain. gotacacs rejects unknown types and drops `*` AV pairs. wxccs rejects unknown flag bits and is an unproven module with a large extra surface. Wrapping either to the TacLab API is not cheaper than an internal codec.

### Fork a candidate and maintain a packet-only subset

Rejected as the default. A fork still needs an owner, an upstream strategy, and a full TacLab regression suite. Revisit only if in-tree conformance proves unachievable (see ADR 0001’s external-daemon fallback).

### External TACACS daemon + Go management plane

Rejected as the default (ADR 0001). It splits the in-memory overlay and REST/MCP parity. Still a last-resort fallback if an in-process codec cannot meet release gates.

## Compatibility impact

- No production dependency or public codec API is introduced.
- On-wire compatibility is defined by RFC 8907 / RFC 9887 and TacLab golden fixtures, not by matching a library’s quirks.
- Operators do not configure a codec backend.

## Migration

There is no prior codec to migrate. If a future ADR selects a library:

1. The library may implement only encode/decode behind `internal/tacacs/codec`.
2. Pin the module version in `go.mod` and record it here.
3. Re-run header/body fuzz seeds, race tests, and independent testclient fixtures.
4. Keep `internal/tacacs/testclient/codec` as a separate implementation.

## Configuration impact

None. Listener, secret, and TLS keys are unchanged. There is no `codec.backend` setting.

## Test impact

- `testdata/protocol/fuzz/header/` holds 12-byte valid and junk header seeds used by production `FuzzHeader`.
- `testdata/protocol/header/` and `testdata/protocol/obfuscation/` hold independent golden vectors (Python `hashlib.md5` for the pad).
- `tools/spike` remains an evaluation harness only.
- `make bench` runs header decode/encode and 64 B / 1 KiB obfuscation benches under `internal/tacacs/codec`.
- Production fuzz smoke is `go test ./internal/tacacs/... -run 'Fuzz'` (seed corpora as unit tests).

## Performance impact

Header decode/encode and 64 B / 1 KiB obfuscation benches live under `internal/tacacs/codec`. Spike benches remain evaluation-only. Production budgets stay in `benchmarks/budgets.yaml` after the first recorded baseline.

## Documentation impact

- This ADR is the codec-approach record.
- `docs/REFERENCES.md` points here for the evaluation outcome.
- `docs/ARCHITECTURE.md` states that `internal/tacacs/codec` is internal and that `tools/spike` is not production.
- `docs/TASKS.md` P1 records the decision. Packet completeness remains P3.

## Revisit conditions

Revisit when any of the following occurs:

- The pinned Go toolchain moves to a version that can import a candidate without an extra upgrade ADR.
- A candidate publishes an isolated, versioned encode/decode module with panic-free bounded reads, unknown-type §3.6 replies, ignored unknown flags, and both AV separators — demonstrated by TacLab fixtures.
- In-tree conformance is shown to be unachievable and an external daemon fallback is approved.
- RFC 8907 or RFC 9887 changes header or obfuscation rules.

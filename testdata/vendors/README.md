# Vendor authorization fixtures

Sanitized, representative TACACS+ authorization AV shapes used by lab
network operating systems. These are **not** live packet captures and
contain no hostnames, serials, community strings, or secrets.

Provenance is vendor documentation and common lab NAS behavior:

| ID prefix | Source | Notes |
|---|---|---|
| `cisco-ios-xe` | Cisco IOS-XE TACACS+ command authorization | `service=shell`, empty `cmd` for session, `cisco-av-pair` roles |
| `juniper-junos` | Juniper Junos remote authorization | `service=junos-exec` plus allow/deny command attributes |
| `arista-eos` | Arista EOS exec authorization | Cisco-like shell session plus `cmd`/`cmd-arg` |

Core policy code must treat unknown names as opaque vendor attributes.
Vendor strings appear only in this directory and tests that load it.

`policy.yaml` is the compiled snapshot for these cases. `fixtures.yaml`
holds request AV lists and expected decisions/response attributes.

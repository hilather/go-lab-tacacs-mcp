# Baseline state — users, groups, clients, and everything else

Status: operator first-setup  
Last updated: 2026-08-14

This is how you configure TacLab **before** devices or agents talk to it. Schema and invariants live in [CONFIGURATION.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CONFIGURATION.md). Day-2 operations stay in [OPERATOR.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/OPERATOR.md). First boot: [QUICKSTART.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/QUICKSTART.md).

There is **no persisted runtime database**. The durable state is files on disk. The process overlay is memory-only and disappears on restart or `runtime.reset`.

---

## 1. What “state files” are

| Role | Path after `labgen` | Survives restart? |
|---|---|---|
| Baseline YAML | `deployments/compose/config/taclab.yaml` | Yes — this **is** the lab |
| TLS-only YAML | `deployments/compose/config/taclab.tls-only.yaml` | Yes — used only with the TLS overlay |
| Secret files | `deployments/compose/secrets/*` | Yes — referenced, never inlined |
| Human password copy | `deployments/compose/secrets/PASSWORDS.txt` (mode `0600`) | Yes — not read by `taclabd` |
| Public certs / CRL | `deployments/compose/certs-public/` | Yes |
| Lab PKI (private) | `deployments/compose/pki/` | Yes — keep off git |
| Compose wiring | `deployments/compose/compose.yaml` | Yes — mounts YAML + Docker secrets |
| Runtime overlay | *(none)* | **No** |

`taclabd` never rewrites the baseline file. Unknown YAML fields fail closed. `schema_version: 1` remains the Compose/labgen default (TACACS-only). `schema_version: 2` is required to enable RADIUS/UDP. `labgen` also writes `taclab.combined.yaml` and `taclab.radius-only.yaml`. Do not advertise complete RADIUS.

Checked-in templates (no secrets): [configs/lab.example.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/configs/lab.example.yaml) (v1) and [configs/lab.example.v2.yaml](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/configs/lab.example.v2.yaml) (combined TACACS + RADIUS). `labgen` writes Compose-ready copies with file refs that match Docker secret names.

---

## 2. Generate, then edit

```bash
git clone https://github.com/hilather/go-lab-tacacs-mcp.git
cd go-lab-tacacs-mcp
go run ./tools/labgen deployments/compose   # or: make lab-gen
```

That materializes unique ≥32-character legacy **and** RADIUS secrets, Argon2id PHC verifiers, one API bearer, and lab PKI. The RADIUS secret is distinct from the TACACS secret. It does not print secret values.

| Generated secret file | Used by |
|---|---|
| `api_admin_token` | Bootstrap REST / MCP / UI bearer |
| `lab_switches_tacacs_secret` | Legacy client `lab-switches` |
| `lab_switches_radius_secret` | RADIUS/UDP endpoint on `lab-switches` (v2 combined / RADIUS-only) |
| `lab_admin_argon2id` | User `lab-admin` ASCII/PAP |
| `lab_admin_enable_argon2id` | User `lab-admin` ENABLE |
| `lab_admin_challenge_secret` | User `lab-admin` CHAP / MS-CHAP |
| `lab_readonly_argon2id` | User `lab-readonly` ASCII/PAP |
| `lab_disabled_argon2id` | User `lab-disabled` (account off) |
| `tacacs_server_key.pem` | Secure TACACS TLS identity |

Plaintext for humans only (not loaded by the daemon):

```text
lab-admin=…
lab-admin-enable=…
lab-readonly=…
lab-disabled=…
lab-admin-challenge=…
```

Do not commit `secrets/`, `pki/`, or `PASSWORDS.txt`.

Validate a candidate without publishing:

```bash
./bin/taclabd validate --config deployments/compose/config/taclab.yaml
# or, after make build
```

Apply an edited bind-mounted YAML:

```bash
# SIGHUP into the container, or:
curl -sS -X POST http://127.0.0.1:8080/api/v1/config/reload \
  -H "Authorization: Bearer ${TOKEN}"
```

**New Docker secret files require `docker compose up -d`** (recreate). Reload alone cannot introduce a secret the Compose file does not already mount under `/run/secrets/<name>`. File-watch reload is off.

---

## 3. Stock personas `labgen` writes

| Object | id | Meaning |
|---|---|---|
| Group | `administrators` | `shell` + `priv-lvl=15`, command `.*` permit |
| Group | `readonly` | `shell` + `priv-lvl=1`; `show` / `ping` / `traceroute`; else deny |
| User | `lab-admin` | TACACS username `lab-admin`, group `administrators`, login + enable + challenge |
| User | `lab-readonly` | Group `readonly`; restricted to clients `lab-switches` and `secure-routers` |
| User | `lab-disabled` | `enabled: false` — present for negative tests |
| Client | `lab-switches` | Legacy, host 49, TACACS shared-secret file, `0.0.0.0/0` + `::/0`. Combined/RADIUS-only profiles add a distinct RADIUS secret on UDP 1812/1813. |
| Client | `secure-routers` | TLS 1.3 mTLS, host 300, SAN `nas.lab.example` |
| Token | `lab-admin` | Bootstrap bearer; all lab scopes except `events:sensitive` |

Generated `source_cidrs` are wide because Docker published ports often SNAT the peer. Narrow them only on host-network / macvlan labs ([LAB_DEPLOYMENT.md](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/LAB_DEPLOYMENT.md) §4.3).

---

## 4. Users (TACACS accounts)

`users[].id` **is** the TACACS username (RFC 8265 UsernameCasePreserved — not lowercased). It is also the MS-CHAP v2 username octet string ([ADR 0002](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0002-password-kdf.md)).

```yaml
users:
  - id: netops
    display_name: Network operations
    enabled: true
    group_ids:
      - readonly
    rules:                    # optional per-user overlay on groups
      services: []
      command_rules: []
    credentials:
      login:
        verifier:
          file: /run/secrets/netops_argon2id
      challenge:              # required for chap / mschapv1 / mschapv2
        secret:
          file: /run/secrets/netops_challenge_secret
      enable:                 # required for ENABLE
        verifier:
          file: /run/secrets/netops_enable_argon2id
    restrictions:
      client_ids: []          # empty = any matching client
      valid_after: null
      valid_before: null
```

| Credential | Methods |
|---|---|
| `credentials.login.verifier` | ASCII LOGIN, PAP, ASCII CHPASS (CHPASS updates **runtime** login only) |
| `credentials.challenge.secret` | CHAP, MS-CHAP v1, MS-CHAP v2 — **not** derived from the Argon2id verifier |
| `credentials.enable.verifier` | ENABLE (type ignored as specified) |

A method listed on the client but missing the matching user material is rejected (`AUTH_METHOD_CREDENTIAL_MISSING`). ASCII/PAP are lab compatibility methods ([ADR 0012](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/decisions/0012-ascii-pap-enablement-warning.md)).

### 4.1 Durable user (files)

1. Write secret files (mode `0444` so Compose UID 10001 can read them; not world-writable).
2. Declare them in `compose.yaml` (service `secrets:` **and** top-level `secrets:`).
3. Add the `users[]` object to `config/taclab.yaml`.
4. `taclabd validate`, then `docker compose up -d`, then `config.reload` if you only changed YAML.

There is **no** `taclabd hash` subcommand in 1.0. Two supported ways to get a verifier:

**A. Runtime (ephemeral)** — UI Users page, `POST /api/v1/users`, or `taclab.users.create`. Submit the password once; TacLab stores Argon2id and never returns it. Gone after restart / `runtime.reset`.

**B. Durable PHC file** — encode with the same package `labgen` uses (`m=65536` KiB, `t=3`, `p=1`):

```bash
# from the repository root
cat > /tmp/mkphc.go <<'EOF'
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run /tmp/mkphc.go <password>")
		os.Exit(2)
	}
	phc, err := credentials.DeriveArgon2id([]byte(os.Args[1]), credentials.DefaultParams, rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(append(phc, '\n'))
}
EOF
go run /tmp/mkphc.go 'your-lab-password' > deployments/compose/secrets/netops_argon2id
chmod 0444 deployments/compose/secrets/netops_argon2id
```

Challenge secrets are **clear-equivalent** bytes in a file (not hashed). Generate with `openssl rand -base64 32`. ENABLE is a separate Argon2id PHC.

### 4.2 Compose wiring for a new secret

```yaml
# deployments/compose/compose.yaml — under services.taclab.secrets:
      - netops_argon2id

# and under top-level secrets:
  netops_argon2id:
    file: ./secrets/netops_argon2id
```

Inside the container the path is `/run/secrets/netops_argon2id`. That is what YAML `file:` must name.

---

## 5. Groups (authorization policy)

Groups are **flat** (no nesting). Evaluation is default-deny on each evaluator:

- `services[]` never authorize a request that carries a non-empty `cmd`.
- `command_rules[]` never decide a session/service request.
- `default_command_action` must be `deny` or omitted.

```yaml
groups:
  - id: netops
    display_name: Network operations
    priority: 50          # lower number wins across groups
    enabled: true
    services:
      - service: shell
        protocol: null
        action: permit    # YAML alias of permit_add
        reply_attributes:
          - name: priv-lvl
            separator: "="   # '=' mandatory, '*' optional
            value: "7"
    command_rules:
      - id: show
        priority: 10        # lower number first inside the group
        action: permit
        command:
          exact: show       # exactly one of exact | pattern per field
        arguments:
          pattern: ".*"
        reason: Operational show
    default_command_action: deny
```

REST/MCP writes use `permit_add` | `permit_replace` | `deny` (not the YAML `permit` alias).

`clients[].authorization.default_group_ids` apply when the user has no groups that match the request. `fallback_rules` (root) is the last-resort rule set; labgen leaves it empty.

Golden checks: `administrators` session → `priv-lvl` 15; `readonly` + `cmd=configure` → deny. Explain with `POST /api/v1/policy/evaluate` or `taclab.policy.evaluate` (`policy:test`).

---

## 6. Clients (devices / NAS)

A client is a device or a CIDR of devices. Match is fail-closed:

1. Transport (`legacy` vs `tls`) must match the listener.
2. TLS: optional `match.certificate.dns_sans` / `ip_sans`.
3. Longest `source_cidrs` prefix (unless `match.mode: certificate_only`).
4. Lowest numeric `priority`.
5. Remaining tie → `CLIENT_MATCH_AMBIGUOUS` (config error).

```yaml
clients:
  - id: closet-sw
    display_name: Wiring-closet switches
    priority: 80
    enabled: true
    match:
      mode: address_and_certificate
      source_cidrs:
        - 10.20.0.0/16
      transports:
        - legacy
    legacy:
      shared_secret:
        file: /run/secrets/closet_sw_tacacs_secret
      shared_secret_lifecycle:
        last_rotated_at: 2026-08-13T00:00:00Z
        rotation_interval: 90d
    authentication:
      allowed_methods: [ascii, pap, chap, mschapv1, mschapv2, enable, ascii_chpass]
      default_service: login
    authorization:
      default_group_ids: [readonly]
    accounting:
      enabled: true
      accept_start: true
      accept_stop: true
      accept_watchdog: true
```

TLS client (no shared secret on the wire):

```yaml
  - id: core-rtr
    match:
      transports: [tls]
      source_cidrs: [10.30.0.0/16]
      certificate:
        dns_sans: [rtr-01.lab.example]
        ip_sans: [10.30.0.11]
```

Issue the device cert from the lab client CA (`tools/labcerts` / `labgen` output under `pki/` and `certs-public/`). Revocation is `configured_crl`.

Legacy secret policy (`security.legacy_shared_secrets`): minimum 16 characters (labgen uses ≥32), ≥3 character classes, reject known-weak values, warn on reuse. Every enabled legacy client needs its **own** secret file.

---

## 7. API tokens (REST / MCP / UI)

Bootstrap tokens live under `api.bootstrap_tokens[]`. The value is a file, never a YAML string.

```yaml
api:
  mode: lab_static_bearer
  bootstrap_tokens:
    - id: lab-admin
      token:
        file: /run/secrets/api_admin_token
      scopes:
        - state:read
        - state:write
        - config:reload
        - config:export
        - policy:test
        - events:read
        - tokens:manage
        - runtime:reset
      expires_at: null
```

Scopes are exact. `state:write` does **not** grant `tokens:manage`, `config:reload`, or `runtime:reset`. Add `events:sensitive` only if the client may see usernames and commands.

Create more tokens at runtime with `tokens:manage` (`POST /api/v1/tokens` / `taclab.tokens.create`). The bearer is returned **once**. Runtime tokens die with the process; put durable operators in `bootstrap_tokens`.

---

## 8. Everything else that is configurable

| Root section | What it controls | Runtime-mutable? |
|---|---|---|
| `metadata` | Name, description, labels (not policy) | Reload |
| `server` | `instance_id`, shutdown grace, log level, fail-closed startup | Reload |
| `runtime` | `persistence: memory`, shadowing, tombstones, rebase, object caps | Reload (caps) |
| `security` | Env-secret switch, strict secret files, legacy secret policy | Reload |
| `listeners.legacy_tacacs` | Bind (container `0.0.0.0:4949`), timeouts, single-connect | Reload / restart |
| `listeners.secure_tacacs` | Bind (`:4300`), TLS 1.3 mTLS, CRL, ticket `0` or `168h` | Reload / restart |
| `listeners.http` | UI / REST / MCP bind `:8080`, body limit, trusted proxies, optional TLS | Reload / restart |
| `api` | Lab bearer mode, cookie session, MCP origins, rate limits | Reload |
| `api.mcp.allowed_origins` | Browser MCP callers; leave empty + `require_origin: false` for desktop agents | Reload |
| `limits` | Username / AV / command / trace / event size caps | Reload |
| `fallback_rules` | Last-resort service/command rules (labgen: empty) | Reload |
| `events` | Ring size (default 10_000), what to include, stdout JSON | Reload |
| `observability` | Metrics `127.0.0.1:9090`, optional `/metrics` on 8080; pprof off | Reload |

Listeners cannot be created or deleted through REST/MCP. Changing bind addresses or TLS identity needs a reload that compiles, often a container recreate.

---

## 9. Two ways to change AAA objects

| Need | How | Lasts across restart? |
|---|---|---|
| Reproducible lab | Edit YAML + secret files, `validate`, Compose recreate if new secrets, `config.reload` | Yes |
| Experiment | UI, REST `/api/v1/users|groups|clients`, MCP `taclab.users.*` / `groups.*` / `clients.*` | **No** |

Runtime objects **replace** a baseline object with the same id (no deep merge) when `runtime.allow_shadowing` is true. Deleting a baseline object through the API writes a tombstone; it does not edit the file. `POST /api/v1/runtime/reset` (`runtime:reset`) drops the overlay.

Mutations take `If-Match` / `expected_revision`. Stale revision → conflict, no write.

---

## 10. Checklist for a new lab identity

- [ ] Group exists (`groups[].id`) with the `priv-lvl` and command rules you want
- [ ] User `id` is the device login name; `group_ids` reference real groups
- [ ] Login PHC file mounted; challenge file if CHAP/MS-CHAP; enable PHC if ENABLE
- [ ] Client `source_cidrs` match the **TCP peer TacLab will see**
- [ ] Legacy client has its own ≥32-char secret file + lifecycle dates
- [ ] TLS client has a cert from the lab client CA and SAN/CIDR match
- [ ] `allowed_methods` ⊆ methods the user can actually satisfy
- [ ] `taclabd validate --config …` is clean
- [ ] New Compose secrets recreated; then `config.reload`
- [ ] Policy explain on a golden permit and a golden deny

Do not put plaintext passwords, shared secrets, or private keys in git, images, or chat logs. `PASSWORDS.txt` is a local operator crib only.

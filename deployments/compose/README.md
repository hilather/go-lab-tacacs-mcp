# Compose lab

Reference deployment for `ghcr.io/hilather/go-lab-tacacs-mcp`.

| File | Role |
|---|---|
| `compose.yaml` | Dual-listener: host 49→4949, 300→4300, 8080→8080, 1812/1813 UDP |
| `compose.tls-only.yaml` | Overlay: TLS-only TACACS, no host port 49 |
| `compose.combined.yaml` | Overlay: schema v2 TACACS + RADIUS/UDP |
| `compose.radius-only.yaml` | Overlay: RADIUS/UDP only, no host 49/300 |
| `compose.lab-test.yaml` | Overlay: high host ports + `integration-tests` |
| `compose.smoke.yaml` | Pre-1.0 high-port smoke without generated PKI |

## Generate secrets and certificates

Private keys and verifiers are not committed.

```bash
go run ./tools/labgen deployments/compose
# or: make lab-gen
```

That writes `config/taclab.yaml`, `config/taclab.tls-only.yaml`, `config/taclab.combined.yaml`, `config/taclab.radius-only.yaml`, `certs-public/`, `secrets/` (including distinct `lab_switches_radius_secret`), and `pki/`. Docker secret files used by UID 10001 are mode `0444` (not world-writable). `secrets/PASSWORDS.txt` and PKI private keys stay mode `0600`. Secrets are never baked into images.

Regenerate: `go run ./tools/labgen -force deployments/compose`.

## Start

```bash
docker compose -f deployments/compose/compose.yaml up -d --build
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.combined.yaml up -d --build
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.radius-only.yaml up -d --build
docker compose -f deployments/compose/compose.yaml -f deployments/compose/compose.tls-only.yaml up -d --build
```

RADIUS/UDP is a lab profile, not complete RADIUS. Keep 1812/1813 off the public internet.

The container runs as UID/GID 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`. Reload is `SIGHUP` or `POST /api/v1/config/reload`. File-watch reload is off.

## Source IP (LAB §4.3)

Client match uses the TCP peer address. `X-Forwarded-For` is never a TACACS match key. Published ports on Linux Docker often SNAT the peer onto the docker bridge.

The generated lab YAML uses `0.0.0.0/0` and `::/0` so compose published-port NAT and service-to-service addresses both match. Before claiming a device-accurate topology:

1. Capture a TACACS session and a connection event.
2. Confirm the address TacLab selected is the device address, not the docker-proxy.
3. If it is not, switch to host networking or macvlan/ipvlan.

`make lab-test` records the observed `client_id` and event `remote` on LAB-SOURCE-001 and fails if either is missing. That field is the TACACS `rem_addr`, not the TCP peer used for match.

## Tests

```bash
make lab-test
```

That builds the image, generates an ephemeral directory, starts a unique Compose project on high host ports, runs LAB-* (including a subscriber that outlives `listeners.http.write_timeout`), restarts, and asserts the overlay is gone.

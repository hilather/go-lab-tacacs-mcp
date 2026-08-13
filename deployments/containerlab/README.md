# Optional Cisco IOL lab (Containerlab)

Status: optional device interop  
Default CI: **skip when absent** — never a Cisco PASS and never device-family completeness.

This is the **suggested** Cisco integration path: [Containerlab](https://containerlab.dev/manual/kinds/cisco_iol/) `cisco_iol` (IOS-on-Linux) as the TACACS+ **client** and TacLab as the TACACS+ **server**. It is **not** GNS3 and **not** dynamips.

## Legal / licensing

Cisco IOL binaries ship on the Cisco Modeling Labs **refplat** ISO (`iol` / `ioll2` / `iol-xe` / `ioll2-xe` directories). Obtain CML-Free (or another licensed CML offering) from Cisco:

- https://developer.cisco.com/modeling-labs/
- https://www.cisco.com/site/us/en/products/networking/software/modeling-labs/index.html

Do **not** commit, vendor, or publish IOL `.bin` files, refplat ISOs, or prebuilt `vrnetlab/cisco_iol` tarballs. This repository never redistributes Cisco software.

## Build a local vrnetlab image

Use the **srl-labs** fork (required by Containerlab), not upstream `vrnetlab/vrnetlab`:

```bash
git clone https://github.com/srl-labs/vrnetlab
cd vrnetlab
# checkout a tag compatible with your containerlab version:
# https://containerlab.dev/manual/vrnetlab/#compatibility-matrix

# From the CML refplat ISO, copy the IOL binary from iol-xe-* or ioll2-xe-*
# into cisco/iol and name it cisco_iol-<version>.bin (or cisco_iol-L2-<version>.bin).
cd cisco/iol
make docker-image
docker images | grep cisco_iol
```

Expected local tags look like `vrnetlab/cisco_iol:17.12.01` (L3) or `vrnetlab/cisco_iol:L2-17.12.01`.

## Run

```bash
export TACLAB_IOL_IMAGE=vrnetlab/cisco_iol:17.12.01   # must already exist locally
# optional: export TACLAB_IMAGE=ghcr.io/hilather/go-lab-tacacs-mcp:dev
make cisco-lab
```

The shipped entry point is `go run ./tools/ciscolab` (`make cisco-lab`).

| Condition | Result |
|---|---|
| `TACLAB_IOL_IMAGE` unset, image not local, or `containerlab` missing | Prints `CISCO-LAB: SKIP — equipment gap: …` and **exits 0**. Required `make lab-test` / `ci-gate` jobs are unaffected. |
| Containerlab + local IOL image present | Deploys this topology, waits for IOL, drives **login** and **ENABLE** against TacLab (exec/command authorization and accounting if the image offers them), writes sanitized evidence, tears down. |

The runner **never** `docker pull`s a Cisco image.

## Topology

- [topo.clab.yaml.tmpl](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/deployments/containerlab/topo.clab.yaml.tmpl) — `cisco_iol` + TacLab `linux` node on a shared mgmt network.
- [iol-aaa.cfg.partial.tmpl](https://github.com/hilather/go-lab-tacacs-mcp/blob/main/deployments/containerlab/iol-aaa.cfg.partial.tmpl) — IOL AAA (legacy TACACS+ TCP 4949) targeting TacLab. Filled only in an ephemeral workdir.

TacLab secrets come from `tools/labgen` (same layout as Compose). IOL Ethernet0/0 lives in VRF `clab-mgmt` (Containerlab default).

TLS TACACS (RFC 9887) is **not** required on this path; IOL TLS support is uncertain.

## Evidence

Skip or live results go to `dist/cisco-lab-evidence.json` (override with `TACLAB_CISCO_EVIDENCE`). The file must not contain shared secrets, passwords, or tokens. A skip record has `"cisco_pass": false` and `"status": "skip"`.

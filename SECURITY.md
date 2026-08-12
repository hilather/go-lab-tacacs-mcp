# Security policy

## Reporting a vulnerability

Do not open a public GitHub issue for security-sensitive reports.

1. Use GitHub Security Advisories for `hilather/go-lab-tacacs-mcp` when enabled.
2. Include: affected version or commit, reproduction steps, impact, and whether credentials or device secrets are involved.
3. Allow a reasonable window for triage before public disclosure.

## Secrets

Never commit TACACS shared secrets, challenge secrets, passwords, API bearer token values, TLS private keys, or session cookies.

Secret-bearing types must not implement unconstrained string formatting. Secret-canary tests are required for every output surface once those surfaces exist.

## Product posture (summary)

- Fail closed on unknown clients, ambiguous client matches, and invalid reloads.
- Legacy TACACS+ and TLS TACACS+ use distinct sockets; no upgrade or fallback.
- Admin CSRF is required whenever cookie authentication is enabled.
- File-watcher reload is off in every reference profile.

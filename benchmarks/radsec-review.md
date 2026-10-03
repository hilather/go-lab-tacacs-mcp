# RadSec CRL validation — RAD-REV-001

Reference: Go 1.26.8, linux/amd64, Intel Core i7-8750H, same issuer/leaf/current empty CRL fixture. Command: `go test ./internal/radius/tls -run '^$' -bench BenchmarkRadSecCRLValidation -benchmem -count=3`.

| Implementation | Median ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Before (serial-only scan) | 4.641 | 0 | 0 |
| After (leaf issuer + CRL signature + validity verification) | 249264 | 1472 | 24 |

The new cost is incurred at a configured-CRL TLS handshake, not per RADIUS packet. The old benchmark skipped authentication entirely and therefore measured an empty scan. The added signature-verification cost is required to fail closed; retaining the old behavior for speed would remove the CRL security boundary. Regression exceeds ordinary hot-path budgets; the root reviewer approved this handshake-only security explanation on 2026-10-03. No credential cost was reduced.

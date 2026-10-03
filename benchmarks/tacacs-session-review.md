# TACACS session safety — TAC-REV-001

Reference: Go 1.26.8, linux/amd64, Intel Core i7-8750H. Same command and fixture before/after: `go test ./internal/tacacs/server -run '^$' -bench BenchmarkDispatchAuthorSingleConnect -benchmem -count=3`.

| Implementation | ns/op samples | Median ns/op | Median B/op | allocs/op |
|---|---|---:|---:|---:|
| Before | 353772, 261567, 287446 | 287446 | 5369 | 85 |
| After | 171904, 130194, 132711 | 132711 | 5525 | 85 |

Equivalent median comparison: latency -53.8%, bytes +2.9%, allocations unchanged. Other agents were running checks concurrently, so these noisy samples do not establish a performance improvement; they show no measured regression exceeding the budgets. The fix adds one boolean negotiation check and removes an unsafe cross-goroutine write. No policy or credential work was removed.
